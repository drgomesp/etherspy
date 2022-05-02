package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
)

var Version string

func init() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	if Version != "" {
		log.Info().Msgf("build: %s\t", Version)
	}
}

func main() {
	log.Debug().Msg("kurwa!")
}
