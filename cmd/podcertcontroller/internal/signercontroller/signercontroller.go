// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signercontroller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/rendezvous"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	certinformersv1beta1 "k8s.io/client-go/informers/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	certlistersv1beta1 "k8s.io/client-go/listers/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/clock"
)

type SignerImpl interface {
	SignerName() string
	DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error)
	MakeCert(context.Context, *certsv1beta1.PodCertificateRequest) error
}

type Hasher interface {
	AssignedToThisReplica(ctx context.Context, item string) bool
}

// Controller is an in-memory signing controller for PodCertificateRequests.
type Controller struct {
	clock clock.PassiveClock

	kc          kubernetes.Interface
	pcrInformer cache.SharedIndexInformer
	pcrQueue    workqueue.TypedRateLimitingInterface[string]

	hasher Hasher

	handler SignerImpl

	// trustBundleConfigMapNamespace, when non-empty, is the namespace
	// ensureBundles additionally mirrors each desired ClusterTrustBundle into
	// as a ConfigMap -- for clusters where ClusterTrustBundle itself is
	// unavailable. Empty disables the mirror.
	trustBundleConfigMapNamespace string
}

// New creates a new Controller. When trustBundleConfigMapNamespace is
// non-empty, RunTrustBundlePublisher additionally mirrors each of the
// handler's desired ClusterTrustBundles into a ConfigMap of the same name
// (with '/' and ':' replaced by '-', since those are valid in a
// ClusterTrustBundle name but not a ConfigMap name) in that namespace, keyed
// "trust-bundle.pem" -- the same file name every existing consumer already
// mounts a ClusterTrustBundle-projected trust bundle at.
func New(clock clock.PassiveClock, handler SignerImpl, kc kubernetes.Interface, hasher Hasher, trustBundleConfigMapNamespace string) *Controller {
	pcrInformer := certinformersv1beta1.NewFilteredPodCertificateRequestInformer(kc, metav1.NamespaceAll, 24*time.Hour, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
		func(opts *metav1.ListOptions) {
		},
	)

	sc := &Controller{
		clock:                         clock,
		kc:                            kc,
		pcrInformer:                   pcrInformer,
		pcrQueue:                      workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		handler:                       handler,
		hasher:                        hasher,
		trustBundleConfigMapNamespace: trustBundleConfigMapNamespace,
	}

	sc.pcrInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, err := cache.MetaNamespaceKeyFunc(new)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
		DeleteFunc: func(old any) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(old)
			if err != nil {
				return
			}
			sc.pcrQueue.Add(key)
		},
	})

	return sc
}

// Run watches and signs PodCertificateRequests. It blocks until ctx is
// canceled.
//
// It does not return until ctx is canceled even when the
// PodCertificateRequest API is unavailable (e.g. its feature gates are not
// enabled on a managed control plane): cache.WaitForCacheSync below polls
// against ctx.Done() and otherwise runs for as long as the reflector keeps
// failing to sync, which on such a cluster is forever. Callers that also need
// trust-bundle publishing to make progress on such a cluster must run
// RunTrustBundlePublisher independently rather than relying on it being
// reachable from here -- it used to be started from inside Run, behind this
// same wait, which meant it silently never ran at all on those clusters.
func (c *Controller) Run(ctx context.Context, workers int) {
	defer c.pcrQueue.ShutDown()
	go c.pcrInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrInformer.HasSynced) {
		return
	}

	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		go wait.UntilWithContext(ctx, c.runWorker, time.Second)
	}
	<-ctx.Done()
}

// RunTrustBundlePublisher periodically publishes the handler's desired trust
// bundles. Unlike Run, it depends on nothing but the handler's already-loaded
// CA pool and ordinary (non-watch) API calls, so it makes progress even on a
// cluster where PodCertificateRequest itself is unavailable. It blocks until
// ctx is canceled.
func (c *Controller) RunTrustBundlePublisher(ctx context.Context) {
	wait.JitterUntilWithContext(ctx, c.ensureBundles, 5*time.Second, 1.0, true)
}

func (c *Controller) runWorker(ctx context.Context) {
	for c.processNextWorkItem(ctx) {
	}
}

func (c *Controller) processNextWorkItem(ctx context.Context) bool {
	key, quit := c.pcrQueue.Get()
	if quit {
		return false
	}
	defer c.pcrQueue.Done(key)

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		slog.ErrorContext(ctx, "Error splitting key into namespace and name",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		return true
	}

	pcr, err := certlistersv1beta1.NewPodCertificateRequestLister(c.pcrInformer.GetIndexer()).PodCertificateRequests(namespace).Get(name)
	if k8serrors.IsNotFound(err) {
		c.pcrQueue.Forget(key)
		return true
	} else if err != nil {
		slog.ErrorContext(ctx, "Error while retrieving PodCertificateRequest",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		return true
	}

	err = c.handlePCR(ctx, pcr)
	if errors.Is(err, rendezvous.ErrNotAssigned) {
		c.pcrQueue.AddRateLimited(key)
		return true
	}
	if err != nil {
		slog.ErrorContext(ctx, "Error while handling PodCertificateRequest",
			slog.String("err", err.Error()),
			slog.String("key", key),
		)
		c.pcrQueue.AddRateLimited(key)
		return true
	}

	c.pcrQueue.Forget(key)
	return true
}

func (c *Controller) handlePCR(ctx context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	if pcr.Spec.SignerName != c.handler.SignerName() {
		// Return nil, since we are not going to magically start supporting this
		// signer name by retaining the cert in the workqueue.
		return nil
	}

	// PodCertificateRequests don't have an approval stage, and the node
	// restriction / isolation check is handled by kube-apiserver.

	for _, cond := range pcr.Status.Conditions {
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeIssued {
			return nil
		}
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeDenied {
			return nil
		}
		if cond.Type == certsv1beta1.PodCertificateRequestConditionTypeFailed {
			return nil
		}
	}

	if !c.hasher.AssignedToThisReplica(ctx, pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name) {
		return rendezvous.ErrNotAssigned
	}

	slog.InfoContext(ctx, "Processing PCR", slog.String("key", pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name))

	err := c.handler.MakeCert(ctx, pcr)
	if err != nil {
		return fmt.Errorf("while converting PodCertificateRequest to x509.Certificate chain: %w", err)
	}

	return nil
}

func (c *Controller) ensureBundles(ctx context.Context) {
	// Only one replica should try to maintain the trust bundles.
	if !c.hasher.AssignedToThisReplica(ctx, "maintain-trust-bundles") {
		return
	}

	wantCTBs, err := c.handler.DesiredClusterTrustBundles()
	if err != nil {
		slog.ErrorContext(ctx, "Error while retrieving CA trust anchors",
			slog.String("err", err.Error()),
			slog.String("signer", c.handler.SignerName()),
		)
		return
	}

	// Each of the two writes below is independent and best-effort: a cluster
	// missing the ClusterTrustBundle API entirely must still get a working
	// ConfigMap mirror, and vice versa, so neither write's failure skips the
	// other, and a failure on one bundle does not skip the rest. There is no
	// hang risk in retrying every tick -- unlike Run's informer sync, these
	// are ordinary Get/Create/Update calls, which fail fast when the API
	// itself is unavailable rather than blocking.
	for _, wantCTB := range wantCTBs {
		c.ensureClusterTrustBundle(ctx, wantCTB)
		c.ensureTrustBundleConfigMap(ctx, wantCTB)
	}
}

func (c *Controller) ensureClusterTrustBundle(ctx context.Context, wantCTB *certsv1beta1.ClusterTrustBundle) {
	ctb, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, wantCTB.ObjectMeta.Name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		if _, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, wantCTB, metav1.CreateOptions{}); err != nil {
			slog.ErrorContext(ctx, "Error while creating ClusterTrustBundle",
				slog.String("err", err.Error()),
				slog.String("key", wantCTB.ObjectMeta.Name),
			)
		}
		return
	} else if err != nil {
		// Best-effort: on a cluster where this API is unavailable at all
		// (e.g. its feature gates are unset), this fails the same way every
		// tick and the ConfigMap mirror below is what actually distributes
		// trust there.
		slog.WarnContext(ctx, "Error while getting ClusterTrustBundle",
			slog.String("err", err.Error()),
			slog.String("key", wantCTB.ObjectMeta.Name),
		)
		return
	}

	if apiequality.Semantic.DeepEqual(wantCTB.Labels, ctb.Labels) && apiequality.Semantic.DeepEqual(wantCTB.Spec, ctb.Spec) {
		return
	}

	ctb = ctb.DeepCopy()
	ctb.ObjectMeta.Labels = wantCTB.Labels
	ctb.Spec.TrustBundle = wantCTB.Spec.TrustBundle

	if _, err := c.kc.CertificatesV1beta1().ClusterTrustBundles().Update(ctx, ctb, metav1.UpdateOptions{}); err != nil {
		slog.ErrorContext(ctx, "Error while updating ClusterTrustBundle",
			slog.String("err", err.Error()),
			slog.String("key", wantCTB.ObjectMeta.Name),
		)
	}
}

// trustBundleConfigMapReplacer maps a ClusterTrustBundle name to a valid
// ConfigMap name: '/' (from the signer name embedded in the CTB name) and
// ':' are both valid in a ClusterTrustBundle name but not in a ConfigMap
// name (an RFC 1123 DNS subdomain).
var trustBundleConfigMapReplacer = strings.NewReplacer("/", "-", ":", "-")

// trustBundleConfigMapDataKey is the ConfigMap key the mirrored trust bundle
// is stored under -- the same file name every existing consumer already
// mounts a ClusterTrustBundle-projected trust bundle at, so a ConfigMap
// volume can be mounted in its place with no path changes.
const trustBundleConfigMapDataKey = "trust-bundle.pem"

func (c *Controller) ensureTrustBundleConfigMap(ctx context.Context, wantCTB *certsv1beta1.ClusterTrustBundle) {
	if c.trustBundleConfigMapNamespace == "" {
		return
	}

	name := trustBundleConfigMapReplacer.Replace(wantCTB.ObjectMeta.Name)
	wantCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: c.trustBundleConfigMapNamespace,
			Labels:    wantCTB.ObjectMeta.Labels,
		},
		Data: map[string]string{trustBundleConfigMapDataKey: wantCTB.Spec.TrustBundle},
	}

	cms := c.kc.CoreV1().ConfigMaps(c.trustBundleConfigMapNamespace)
	cm, err := cms.Get(ctx, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		if _, err := cms.Create(ctx, wantCM, metav1.CreateOptions{}); err != nil {
			slog.ErrorContext(ctx, "Error while creating trust bundle ConfigMap mirror",
				slog.String("err", err.Error()),
				slog.String("key", c.trustBundleConfigMapNamespace+"/"+name),
			)
		}
		return
	} else if err != nil {
		slog.ErrorContext(ctx, "Error while getting trust bundle ConfigMap mirror",
			slog.String("err", err.Error()),
			slog.String("key", c.trustBundleConfigMapNamespace+"/"+name),
		)
		return
	}

	if apiequality.Semantic.DeepEqual(wantCM.Labels, cm.Labels) && apiequality.Semantic.DeepEqual(wantCM.Data, cm.Data) {
		return
	}

	cm = cm.DeepCopy()
	cm.ObjectMeta.Labels = wantCM.Labels
	cm.Data = wantCM.Data

	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		slog.ErrorContext(ctx, "Error while updating trust bundle ConfigMap mirror",
			slog.String("err", err.Error()),
			slog.String("key", c.trustBundleConfigMapNamespace+"/"+name),
		)
	}
}
