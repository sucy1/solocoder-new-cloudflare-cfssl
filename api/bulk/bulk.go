// Package bulk implements the HTTP handler for bulk certificate signing.
package bulk

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// SignResult represents the result of a single sign request in a bulk operation.
type SignResult struct {
	Index       int                    `json:"index"`
	Success     bool                   `json:"success"`
	Certificate string                 `json:"certificate,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Handler accepts a JSON array of sign requests and processes each one.
type Handler struct {
	signer signer.Signer
}

// NewHandlerFromSigner creates a new bulk Handler from a signer.
func NewHandlerFromSigner(s signer.Signer) (h *api.HTTPHandler, err error) {
	policy := s.Policy()
	if policy == nil {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	haveUnauth := (policy.Default.Provider == nil)
	for _, profile := range policy.Profiles {
		haveUnauth = haveUnauth || (profile.Provider == nil)
	}

	if !haveUnauth {
		err = errors.New(errors.PolicyError, errors.InvalidPolicy)
		return
	}

	return &api.HTTPHandler{
		Handler: &Handler{
			signer: s,
		},
		Methods: []string{"POST"},
	}, nil
}

type signRequest struct {
	Hostname    string          `json:"hostname"`
	Hosts       []string        `json:"hosts"`
	Request     string          `json:"certificate_request"`
	Subject     *signer.Subject `json:"subject,omitempty"`
	Profile     string          `json:"profile"`
	Label       string          `json:"label"`
	Bundle      bool            `json:"bundle"`
	ReturnChain bool            `json:"return_chain,omitempty"`
}

func (sr signRequest) toSignRequest() signer.SignRequest {
	if sr.Hostname != "" {
		return signer.SignRequest{
			Hosts:       signer.SplitHosts(sr.Hostname),
			Subject:     sr.Subject,
			Request:     sr.Request,
			Profile:     sr.Profile,
			Label:       sr.Label,
			ReturnChain: sr.ReturnChain,
		}
	}

	return signer.SignRequest{
		Hosts:       sr.Hosts,
		Subject:     sr.Subject,
		Request:     sr.Request,
		Profile:     sr.Profile,
		Label:       sr.Label,
		ReturnChain: sr.ReturnChain,
	}
}

// Handle processes a bulk sign request.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("bulk sign request received")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	var requests []signRequest
	err = json.Unmarshal(body, &requests)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse bulk sign request: expected JSON array")
	}

	if len(requests) == 0 {
		return errors.NewBadRequestString("Empty bulk sign request array")
	}

	results := make([]SignResult, 0, len(requests))
	successCount := 0

	for i, req := range requests {
		result := SignResult{Index: i}

		if req.Request == "" {
			result.Error = "missing parameter 'certificate_request'"
			results = append(results, result)
			continue
		}

		profile, err := signer.Profile(h.signer, req.Profile)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		if profile.Provider != nil {
			result.Error = "profile requires authentication"
			results = append(results, result)
			continue
		}

		signReq := req.toSignRequest()
		cert, err := h.signer.Sign(signReq)
		if err != nil {
			log.Warningf("bulk: failed to sign request %d: %v", i, err)
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		result.Success = true
		result.Certificate = string(cert)
		results = append(results, result)
		successCount++
	}

	log.Infof("bulk sign completed: %d/%d successful", successCount, len(requests))

	return api.SendResponse(w, map[string]interface{}{
		"results":   results,
		"total":     len(requests),
		"succeeded": successCount,
		"failed":    len(requests) - successCount,
	})
}
