package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"sync"
  "strconv"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	ec_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	waf_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/waf/v3"
	es_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	es_extension_v3 "github.com/envoyproxy/go-control-plane/envoy/service/extension/v3"
)

// service ExtensionConfigDiscoveryService {
//   option (envoy.annotations.resource).type = "envoy.config.core.v3.TypedExtensionConfig";
//
//   rpc StreamExtensionConfigs(stream discovery.v3.DiscoveryRequest)
//       returns (stream discovery.v3.DiscoveryResponse) {
//   }
//
//   rpc DeltaExtensionConfigs(stream discovery.v3.DeltaDiscoveryRequest)
//       returns (stream discovery.v3.DeltaDiscoveryResponse) {
//   }
//
//   rpc FetchExtensionConfigs(discovery.v3.DiscoveryRequest)
//       returns (discovery.v3.DiscoveryResponse) {
//     option (google.api.http).post = "/v3/discovery:extension_configs";
//     option (google.api.http).body = "*";
//   }
// }

// YAML equivalent we want to generate for the WAF filter configuration:
//
// resources:
// - '@type': type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig
//   name: waf
//   typed_config:
//     '@type': type.googleapis.com/envoy.extensions.filters.http.waf.v3.WAF
//     signatures:
//     - category:
//         sqli:
//           subcategory: statement_injection
//       certainity: 5
//       id: 1
//       msg: dangerous query
//       name: '1'
//       operand: dangerousquery
//       severity: 5
//     - category:
//         sqli:
//           subcategory: statement_injection
//       certainity: 5
//       id: 2
//       msg: hacker query
//       name: '2'
//       operand: ahackerwashere
//       severity: 5
// version_info: '0'

type ECDSServer struct {
	es_extension_v3.UnimplementedExtensionConfigDiscoveryServiceServer
}

func getWAFDefaultConfig() *waf_v3.WAF {
	return &waf_v3.WAF{
		Signatures: []*waf_v3.WAFSignature{
			{
				Id: 1, Msg: "dangerous query", Name: "1", Operand: "dangerousquery",
				Severity: 5, Category: &waf_v3.WAFCategory{Category: &waf_v3.WAFCategory_Generic{}},
			},
		},
	}
}

func getTypedExtensionConfig(waf_config *waf_v3.WAF) (*ec_core_v3.TypedExtensionConfig, string, error) {
	any_conf, err := ptypes.MarshalAny(waf_config)
	if err != nil {
		return nil, "", err
	}

	ret := &ec_core_v3.TypedExtensionConfig{Name: "waf", TypedConfig: any_conf}

	// Compute hash
	buf, err := proto.Marshal(ret)
	if err != nil {
		return nil, "", err
	}

	hash := sha256.Sum256(buf)
	version := base64.StdEncoding.EncodeToString(hash[:])
	return ret, version, nil
}

func getDefaultTypedExtensionConfig() (*ec_core_v3.TypedExtensionConfig, string, error) {
	return getTypedExtensionConfig(getWAFDefaultConfig())
}

type FilterConfig struct {
	version string
	config  *ec_core_v3.TypedExtensionConfig
  // TODO: RWMutex
	mu      sync.Mutex
	newConf *sync.Cond
}

func NewFilterConfig() *FilterConfig {
	ret := &FilterConfig{}
	ret.newConf = sync.NewCond(&ret.mu)
	return ret
}

func (c *FilterConfig) Lock() {
	c.mu.Lock()
}

func (c *FilterConfig) Unlock() {
	c.mu.Unlock()
}

var g_config *FilterConfig = NewFilterConfig()

const TypedExtensionConfigUrl = "type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig"

func generateResponse(config *FilterConfig) (*es_discovery_v3.DiscoveryResponse, error) {
  any_cfg, err := ptypes.MarshalAny(config.config)
  if err != nil {
    return nil, err
  }
  resp := &es_discovery_v3.DiscoveryResponse{
    Resources:   []*anypb.Any{any_cfg},
    TypeUrl:     TypedExtensionConfigUrl,
    VersionInfo: config.version,
  }

  return resp, nil
}

func sendResponse(stream es_extension_v3.ExtensionConfigDiscoveryService_StreamExtensionConfigsServer, resp *es_discovery_v3.DiscoveryResponse, nonce *int) error {
  resp.Nonce = strconv.Itoa(*nonce)

  log.Printf("send configuration: version = %s, nonce = %s\n", resp.VersionInfo, resp.Nonce)
  stream.Send(resp)

  // Send until ack'd
  for {
    ack, err := stream.Recv()
    if err != nil {
      return err
    }
    if ack.TypeUrl != TypedExtensionConfigUrl {
      return errors.New("unsupported type")
    }
    if ack.VersionInfo == resp.VersionInfo && ack.ResponseNonce == resp.Nonce {
      log.Printf("ack ok!")
      break
    }
    log.Printf("ack not ok, resend with a new nonce!")
    *nonce += 1
    resp.Nonce = strconv.Itoa(*nonce)
    stream.Send(resp)
  }
  *nonce += 1

  return nil
}

func (s *ECDSServer) StreamExtensionConfigs(stream es_extension_v3.ExtensionConfigDiscoveryService_StreamExtensionConfigsServer) error {
	log.Printf("StreamExtensionConfigs")
  nonce := 0
  in, err := stream.Recv()
  if err == io.EOF {
    return nil
  }
  if err != nil {
    return err
  }
  if in.TypeUrl != TypedExtensionConfigUrl {
    return errors.New("unsupported type")
  }

  g_config.Lock()
  version := g_config.version
  if in.VersionInfo != version {
    data, err := generateResponse(g_config)
    g_config.Unlock()
    if err != nil {
      return err
    }
    err = sendResponse(stream, data, &nonce)
    if err != nil {
      return err
    }
  } else {
    g_config.Unlock()
  }

  for {
    g_config.Lock()
    g_config.newConf.Wait()
    data, err := generateResponse(g_config)
    g_config.Unlock()
    if err != nil {
      return err
    }
    err = sendResponse(stream, data, &nonce)
    if err != nil {
      return err
    }
  }
}

func (s *ECDSServer) DeltaExtensionConfigs(stream es_extension_v3.ExtensionConfigDiscoveryService_DeltaExtensionConfigsServer) error {
	log.Printf("DeltaDiscoveryRequest")
	return errors.New("unsupported")
}

func (s *ECDSServer) FetchExtensionConfigs(ctx context.Context, req *es_discovery_v3.DiscoveryRequest) (*es_discovery_v3.DiscoveryResponse, error) {
	log.Printf("FetchDiscoveryRequest")
	return nil, errors.New("unsupported")
}

func newConfHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/" {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	conf := &waf_v3.WAF{}
	// TODO: check if we can unmarshal from a stream directly (w/o putting
	// everything into a memory buffer)
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to read data: %s\n", err.Error()), http.StatusInternalServerError)
	}
	err = protojson.Unmarshal(buf, conf)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to parse configuration: %s\n", err.Error()), http.StatusBadRequest)
		return
	}

	gconf, version, err := getTypedExtensionConfig(conf)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable to parse configuration: %s\n", err.Error()), http.StatusBadRequest)
		return
	}

	g_config.Lock()
  defer g_config.Unlock()

	if version == g_config.version {
		return
	}

	g_config.version = version
	g_config.config = gconf
	g_config.newConf.Broadcast()
}

func main() {
	typed_ext_cfg, version, err := getDefaultTypedExtensionConfig()
	if err != nil {
		log.Print("error getting original conf\n")
		return
	}
	g_config.config = typed_ext_cfg
	g_config.version = version

	// HTTP ECDSServer to push configurations
	log.Print("starting HTTP ECDSServer...\n")
	http.HandleFunc("/", newConfHandler)
	go http.ListenAndServe("127.0.0.1:18001", nil)

	// ECDS gRPC ECDSServer
	port := flag.Int("port", 18000, "gRPC port")

	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", *port))
	if err != nil {
		log.Fatalf("failed to listen to %d: %v", *port, err)
	}

	gs := grpc.NewServer()

	es_extension_v3.RegisterExtensionConfigDiscoveryServiceServer(gs, &ECDSServer{})

	log.Printf("starting gRPC ECDSServer on: %d\n", *port)

	gs.Serve(lis)
}
