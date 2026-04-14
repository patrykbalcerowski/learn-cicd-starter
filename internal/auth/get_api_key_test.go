package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Definiujemy przypadki testowe
	tests := []struct {
		name        string      // Nazwa testu (ułatwia szukanie błędów)
		headers     http.Header // Dane wejściowe
		wantKey     string      // Oczekiwany klucz
		wantErr     bool        // Czy spodziewamy się błędu?
		wantErrText string      // Jaki konkretnie błąd ma wrócić?
	}{
		{
			name:        "Brak nagłówka Authorization",
			headers:     http.Header{},
			wantKey:     "",
			wantErr:     true,
			wantErrText: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "Błędny przedrostek (np. Bearer zamiast ApiKey)",
			headers:     http.Header{"Authorization": []string{"Bearer tajny-token-123"}},
			wantKey:     "",
			wantErr:     true,
			wantErrText: "malformed authorization header",
		},
		{
			name:        "Sklejony tekst (brak spacji)",
			headers:     http.Header{"Authorization": []string{"ApiKeytajny-token-123"}},
			wantKey:     "",
			wantErr:     true,
			wantErrText: "malformed authorization header",
		},
		{
			name:        "Pusty nagłówek",
			headers:     http.Header{"Authorization": []string{""}},
			wantKey:     "",
			wantErr:     true,
			wantErrText: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:        "Poprawny nagłówek z ApiKey",
			headers:     http.Header{"Authorization": []string{"ApiKey super-tajny-klucz-456"}},
			wantKey:     "super-tajny-klucz-456",
			wantErr:     false,
		},
	}

	// Odpalamy pętlę po wszystkich przypadkach
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// 1. Sprawdzamy czy błąd wystąpił (lub nie) tak jak chcieliśmy
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() błąd = %v, oczekiwano błędu: %v", err, tt.wantErr)
				return // Przerywamy ten konkretny test, bo reszta nie ma sensu
			}

			// 2. Jeśli miał być błąd, sprawdzamy czy to TEN KONKRETNY błąd
			if tt.wantErr && err.Error() != tt.wantErrText {
				t.Errorf("GetAPIKey() komunikat błędu = '%v', oczekiwano '%v'", err.Error(), tt.wantErrText)
			}

			// 3. Sprawdzamy, czy wyciągnięty klucz jest poprawny
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() zwrócony klucz = %v, oczekiwano %v", gotKey, tt.wantKey)
			}
		})
	}
}