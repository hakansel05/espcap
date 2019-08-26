#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "usage: template.sh node"
    exit
fi

curl -H 'Content-Type: application/json' -XPUT 'http://'$1'/_template/packets' -d '
{
  "index_patterns": ["packets-*"],
  "mappings": {
      "dynamic": "false",
      "properties": {
        "timestamp": {
          "type": "date"
        },
        "layers": {
          "properties": {
            "frame": {
              "properties": {
                "frame_interface_id_frame_interface_name": {
                  "type": "keyword"
                },
                "frame_frame_protocols": {
                  "type": "text",
                  "analyzer": "simple"
                }
              }
            },
            "ip": {
              "properties": {
                "ip_ip_src": {
                  "type": "ip"
                },
                "ip_ip_dst": {
                  "type": "ip"
                },
                "ip_ip_version": {
                  "type": "long"
                }
              }
            },
            "udp": {
              "properties": {
                "udp_udp_srcport": {
                  "type": "long"
                },
                "udp_udp_dstport": {
                  "type": "long"
                }
              }
            },
            "tcp": {
              "properties": {
                "tcp_tcp_srcport": {
                  "type": "long"
                },
                "tcp_tcp_dstport": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_str": {
                  "type": "keyword"
                },
                "tcp_flags_tcp_flags_urg": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_ack": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_push": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_reset": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_syn": {
                  "type": "long"
                },
                "tcp_flags_tcp_flags_fin": {
                  "type": "long"
                },
                "tcp_tcp_seq": {
                  "type": "long"
                },
                "tcp_tcp_ack": {
                  "type": "long"
                },
                "tcp_tcp_window_size": {
                  "type": "long"
                }
              }
            }
          }
        }
      }
    }
  }'

echo
