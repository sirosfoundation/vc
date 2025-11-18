package httpserver

import (
	"context"
	"net/http"
	"time"
	"vc/internal/issuer/apiv1"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/saml"
	"vc/pkg/trace"

	// swagger docs
	_ "vc/docs/issuer"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Service is the service object for httpserver
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	server      *http.Server
	apiv1       Apiv1
	gin         *gin.Engine
	tracer      *trace.Tracer
	httpHelpers *httphelpers.Client
	samlService *saml.Service
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, samlService *saml.Service, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       apiv1,
		gin:         gin.New(),
		server:      &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
		tracer:      tracer,
		samlService: samlService,
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Issuer.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// SAML endpoints (optional - only if SAML is configured)
	if s.samlService != nil {
		rgSAML := rgRoot.Group("/saml")
		s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodGet, "metadata", http.StatusOK, s.endpointSAMLMetadata)
		s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "initiate", http.StatusOK, s.endpointSAMLInitiate)
		s.httpHelpers.Server.RegEndpoint(ctx, rgSAML, http.MethodPost, "acs", http.StatusOK, s.endpointSAMLACS)
		s.log.Info("SAML endpoints enabled", "base_url", s.cfg.Issuer.APIServer.Addr+"/saml")
	}

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.Issuer.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
