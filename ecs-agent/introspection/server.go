// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//	http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package introspection

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/aws/amazon-ecs-agent/ecs-agent/logger"
	"github.com/aws/amazon-ecs-agent/ecs-agent/metrics"
	"github.com/aws/amazon-ecs-agent/ecs-agent/tmds/logging"
)

const (
	Port = 51678
	// With pprof we need to increase the timeout so that there is enough time to do the profiling. Since the profiling
	// time window for CPU is configurable in the request, this timeout effectively means the CPU profiling will be
	// capped to 5 min.
	writeTimeoutForPprof = time.Minute * 5
	pprofBasePath        = "/debug/pprof/"
	pprofCMDLinePath     = pprofBasePath + "cmdline"
	pprofProfilePath     = pprofBasePath + "profile"
	pprofSymbolPath      = pprofBasePath + "symbol"
	pprofTracePath       = pprofBasePath + "trace"
)

var (
	// Injection points for testing
	pprofIndexHandler   = pprof.Index
	pprofCmdlineHandler = pprof.Cmdline
	pprofProfileHandler = pprof.Profile
	pprofSymbolHandler  = pprof.Symbol
	pprofTraceHandler   = pprof.Trace
)

type rootResponse struct {
	AvailableCommands []string
}

// Configuration for Introspection Server
type Config struct {
	readTimeout        time.Duration // http server read timeout
	writeTimeout       time.Duration // http server write timeout
	enableRuntimeStats bool          // enable profiling handlers
}

// Function type for updating Introspection Server config
type ConfigOpt func(*Config)

// Set if Introspection Server should accept profiling requests
func WithRuntimeStats(enableRuntimeStats bool) ConfigOpt {
	return func(c *Config) {
		c.enableRuntimeStats = enableRuntimeStats
	}
}

// Set Introspection Server read timeout
func WithReadTimeout(readTimeout time.Duration) ConfigOpt {
	return func(c *Config) {
		c.readTimeout = readTimeout
	}
}

// Set Introspection Server write timeout
func WithWriteTimeout(writeTimeout time.Duration) ConfigOpt {
	return func(c *Config) {
		c.writeTimeout = writeTimeout
	}
}

// Create a new HTTP Introspection Server
func NewServer(agentState AgentState, metricsFactory metrics.EntryFactory, options ...ConfigOpt) (*http.Server, error) {
	config := new(Config)
	for _, opt := range options {
		opt(config)
	}
	return setup(agentState, metricsFactory, config)
}
func v1HandlersSetup(serverMux *http.ServeMux,
	agentState AgentState,
	metricsFactory metrics.EntryFactory) {
	serverMux.HandleFunc(agentMetadataPath, agentMetadataHandler(agentState, metricsFactory))
	serverMux.HandleFunc(tasksMetadataPath, tasksMetadataHandler(agentState, metricsFactory))
	serverMux.HandleFunc(licensePath, licenseHandler(agentState, metricsFactory))
}
func pprofHandlerSetup(serverMux *http.ServeMux) {
	serverMux.HandleFunc(pprofBasePath, pprofIndexHandler)
	serverMux.HandleFunc(pprofCMDLinePath, pprofCmdlineHandler)
	serverMux.HandleFunc(pprofProfilePath, pprofProfileHandler)
	serverMux.HandleFunc(pprofSymbolPath, pprofSymbolHandler)
	serverMux.HandleFunc(pprofTracePath, pprofTraceHandler)
}
func setup(
	agentState AgentState,
	metricsFactory metrics.EntryFactory,
	config *Config,
) (*http.Server, error) {
	if agentState == nil {
		return nil, errors.New("state cannot be nil")
	}
	if metricsFactory == nil {
		return nil, errors.New("metrics factory cannot be nil")
	}

	paths := []string{agentMetadataPath, tasksMetadataPath, licensePath}

	if config.enableRuntimeStats {
		paths = append(paths, pprofBasePath, pprofCMDLinePath, pprofProfilePath, pprofSymbolPath, pprofTracePath)
	}

	availableCommands := &rootResponse{paths}
	// Autogenerated list of the above serverFunctions paths
	availableCommandResponse, err := json.Marshal(&availableCommands)
	if err != nil {
		logger.Error(fmt.Sprintf("Error marshaling JSON in introspection server setup: %s", err))
	}

	defaultHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Write(availableCommandResponse)
	}

	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/", defaultHandler)

	v1HandlersSetup(serveMux, agentState, metricsFactory)
	if config.enableRuntimeStats {
		pprofHandlerSetup(serveMux)
	}

	loggingServeMux := http.NewServeMux()
	loggingServeMux.Handle("/", logging.NewLoggingHandler(serveMux))

	return &http.Server{
		Addr:         ":" + strconv.Itoa(Port),
		Handler:      panicHandler(loggingServeMux, metricsFactory),
		ReadTimeout:  config.readTimeout,
		WriteTimeout: config.writeTimeout,
	}, nil
}