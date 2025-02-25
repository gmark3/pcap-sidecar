# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG LIBPCAP_VERSION='1.10.5'
ARG TCPDUMP_VERSION='4.99.5'

FROM --platform=linux/amd64 pcap-sidecar:libpcap-v${LIBPCAP_VERSION}_tcpdump-v${TCPDUMP_VERSION}

ARG PCAP_RT_ENV='cloud_run_gen2'

LABEL org.opencontainers.image.description="Cloud Run PCAP sidecar"

USER 0:0

COPY ./bin /bin
COPY ./scripts /scripts
COPY ./tcpdump.conf /tcpdump.conf

RUN sed -i -e "s/@PCAP_RT_ENV@/${PCAP_RT_ENV}/g" /scripts/init && cp -vf /scripts/init /init

ENTRYPOINT ["/init"]
