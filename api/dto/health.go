package dto

// HealthResponse is the JSON body returned by GET /healthz.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}
