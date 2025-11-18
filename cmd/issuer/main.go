package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"vc/internal/issuer/apiv1"
	"vc/internal/issuer/auditlog"
	"vc/internal/issuer/grpcserver"
	"vc/internal/issuer/httpserver"
	"vc/pkg/configuration"
	"vc/pkg/logger"
	"vc/pkg/saml"
	"vc/pkg/trace"
)

type service interface {
	Close(ctx context.Context) error
}

func main() {
	var (
		wg                 = &sync.WaitGroup{}
		ctx                = context.Background()
		services           = make(map[string]service)
		serviceName string = "issuer"
	)

	cfg, err := configuration.New(ctx)
	if err != nil {
		panic(err)
	}

	log, err := logger.New(serviceName, cfg.Common.Log.FolderPath, cfg.Common.Production)
	if err != nil {
		panic(err)
	}

	// main function log
	mainLog := log.New("main")

	tracer, err := trace.New(ctx, cfg, serviceName, log)
	if err != nil {
		panic(err)
	}

	auditLogService, err := auditlog.New(ctx, cfg, log)
	services["auditLogService"] = auditLogService
	if err != nil {
		panic(err)
	}

	apiv1Client, err := apiv1.New(ctx, auditLogService, cfg, tracer, log)
	if err != nil {
		panic(err)
	}

	// Initialize SAML service if enabled
	var samlService *saml.Service
	if cfg.Issuer.SAML.Enabled {
		samlService, err = saml.New(ctx, &cfg.Issuer.SAML, log)
		if err != nil {
			mainLog.Error(err, "Failed to initialize SAML service")
			panic(err)
		}
		mainLog.Info("SAML service initialized", "entity_id", cfg.Issuer.SAML.EntityID)
	} else {
		mainLog.Info("SAML service disabled")
	}

	httpService, err := httpserver.New(ctx, cfg, apiv1Client, tracer, samlService, log)
	services["httpService"] = httpService
	if err != nil {
		panic(err)
	}

	grpcService, err := grpcserver.New(ctx, cfg, apiv1Client, log)
	services["grpcService"] = grpcService
	if err != nil {
		panic(err)
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)

	<-termChan // Blocks here until interrupted

	mainLog.Info("HALTING SIGNAL!")

	for serviceName, service := range services {
		if err := service.Close(ctx); err != nil {
			mainLog.Trace("serviceName", serviceName, "error", err)
		}
	}

	if err := tracer.Shutdown(ctx); err != nil {
		mainLog.Error(err, "Tracer shutdown")
	}

	wg.Wait() // Block here until are workers are done

	mainLog.Info("Stopped")
}
