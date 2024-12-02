/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"flag"
	"os"
	"time"

	lapi "github.com/LINBIT/golinstor/client"
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"golang.org/x/time/rate"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	ctrl "sigs.k8s.io/controller-runtime"
	crtController "sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	piraeusiov1 "github.com/piraeusdatastore/piraeus-operator/v2/api/v1"
	"github.com/piraeusdatastore/piraeus-operator/v2/internal/controller"
	piraeuswebhook "github.com/piraeusdatastore/piraeus-operator/v2/internal/webhook"
	webhookv1 "github.com/piraeusdatastore/piraeus-operator/v2/internal/webhook/v1"
	"github.com/piraeusdatastore/piraeus-operator/v2/pkg/linstorhelper"
	"github.com/piraeusdatastore/piraeus-operator/v2/pkg/vars"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(certmanagerv1.AddToScheme(scheme))

	utilruntime.Must(piraeusiov1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var namespace string
	var pullSecret string
	var imageConfigMapName string
	var linstorApiQps float64
	var nodeCacheDuration time.Duration
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.StringVar(&namespace, "namespace", os.Getenv("NAMESPACE"), "The namespace to create resources in.")
	flag.StringVar(&pullSecret, "pull-secret", os.Getenv("PULL_SECRET"), "The pull secret to use for all containers")
	flag.StringVar(&imageConfigMapName, "image-config-map-name", os.Getenv("IMAGE_CONFIG_MAP_NAME"), "Config map holding default images to use")
	flag.Float64Var(&linstorApiQps, "linstor-api-qps", 100.0, "Limit requests to the LINSTOR API to this many queries per second")
	flag.DurationVar(&nodeCacheDuration, "linstor-node-cache-duration", 1*time.Minute, "Duration for which the results of node and storage pool related API responses should be cached.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	if namespace == "" {
		setupLog.Info("No namespace specified, defaulting to operator namespace")
		raw, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			setupLog.Error(err, "unable to detect operator namespace")
			os.Exit(1)
		}
		namespace = string(raw)
	}

	linstorOpts := []lapi.Option{
		linstorhelper.PerClusterRateLimiter(rate.Limit(linstorApiQps), 1),
		linstorhelper.PerClusterNodeCache(nodeCacheDuration),
	}

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.4/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.18.4/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       vars.OperatorName,
		Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	if err = (&controller.LinstorClusterReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Namespace:          namespace,
		ImageConfigMapName: imageConfigMapName,
		PullSecret:         pullSecret,
		LinstorClientOpts:  linstorOpts,
	}).SetupWithManager(mgr, crtController.Options{}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "LinstorCluster")
		os.Exit(1)
	}
	if err = (&controller.LinstorSatelliteReconciler{
		Client:             mgr.GetClient(),
		Scheme:             mgr.GetScheme(),
		Namespace:          namespace,
		ImageConfigMapName: imageConfigMapName,
		LinstorClientOpts:  linstorOpts,
	}).SetupWithManager(mgr, crtController.Options{}); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "LinstorSatellite")
		os.Exit(1)
	}
	if err = (&controller.LinstorNodeConnectionReconciler{
		Client:            mgr.GetClient(),
		Scheme:            mgr.GetScheme(),
		Namespace:         namespace,
		LinstorClientOpts: linstorOpts,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "LinstorNodeConnection")
		os.Exit(1)
	}
	if err = webhookv1.SetupLinstorClusterWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "LinstorCluster")
		os.Exit(1)
	}
	if err = webhookv1.SetupLinstorSatelliteWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "LinstorSatellite")
		os.Exit(1)
	}
	if err = webhookv1.SetupLinstorSatelliteConfigurationWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "LinstorSatelliteConfiguration")
		os.Exit(1)
	}
	if err = webhookv1.SetupLinstorNodeConnectionWebhookWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "LinstorNodeConnection")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err = ctrl.NewWebhookManagedBy(mgr).
		For(&storagev1.StorageClass{}).
		WithValidator(&piraeuswebhook.StorageClass{}).
		Complete(); err != nil {
		setupLog.Error(err, "unable to create webhook", "webhook", "StorageClass")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager", "version", vars.Version)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
