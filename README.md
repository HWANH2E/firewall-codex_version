# Firewall (C, Stateful Packet Filtering)

이 프로젝트는 리눅스 환경에서 libpcap을 사용하여 네트워크 인터페이스로 유입되는 패킷을 캡처하고, 정의된 방화벽 정책에 따라 허용/차단을 수행하는 Stateful 패킷 필터링 방화벽 예제입니다. TCP 세션 테이블을 유지하여 연결 흐름을 고려한 상태 기반 필터링을 구현합니다.

## 주요 기능
- IPv4 패킷 캡처 및 Ethernet/IP/TCP/UDP 헤더 파싱
- 정책 파일(`rules.conf`)을 읽어 허용/차단 동작 결정
- TCP 플래그 기반의 간단한 상태 머신으로 세션 테이블 관리
- 세션 타임아웃 및 종료 상태 정리
- SIGINT/SIGTERM 수신 시 캡처 루프 안전 종료

## 빌드
```bash
make
```
libpcap 개발 헤더가 필요합니다 (`libpcap-dev` 패키지 등).

## 실행
```bash
sudo ./firewall -i <interface> -r rules.conf
```
- `-i`: 패킷을 캡처할 네트워크 인터페이스
- `-r`: 방화벽 규칙 파일 경로 (기본값: `rules.conf`)

## 규칙 파일 형식
한 줄당 하나의 규칙을 정의하며, 필드는 공백으로 구분됩니다.
```
action protocol src_cidr src_port dst_cidr dst_port [stateful]
```
- `action`: `allow` 또는 `deny`
- `protocol`: `tcp`, `udp`, `icmp`, `any`
- `src_cidr`/`dst_cidr`: `192.168.1.0/24` 같은 CIDR 또는 `any`
- `src_port`/`dst_port`: 0~65535 또는 `any`
- `stateful`: (선택) TCP 규칙에 대해 상태 기반 검사를 적용

### 예시 (`rules.conf`)
```text
# action protocol src_cidr src_port dst_cidr dst_port [stateful]
# SSH 허용 (상태 기반)
allow tcp 192.168.1.0/24 any 0.0.0.0/0 22 stateful
# DNS 허용
allow udp 0.0.0.0/0 any 0.0.0.0/0 53
# 기본 차단
deny any any any any any
```

## 동작 개요
1. `pcap_open_live`로 지정된 인터페이스를 promiscuous 모드로 열고 캡처 루프를 시작합니다.
2. IPv4 패킷만 처리하며, TCP/UDP/ICMP에 대해 규칙 테이블을 확인합니다.
3. TCP 패킷은 세션 테이블을 조회하여 SYN/ACK/FIN/RST 플래그 기반의 상태 전이를 적용합니다. 상태 기반 규칙이 활성화된 경우, 유효한 연결 흐름이 아닐 때 패킷을 차단합니다.
4. 규칙과 상태 검사 결과에 따라 허용/차단 로그를 표준 출력으로 남깁니다.

> 참고: libpcap 기반 사용자 공간 예제이므로 실제 패킷 드롭은 수행하지 않으며, 로그를 통해 허용/차단 여부를 확인할 수 있습니다.
