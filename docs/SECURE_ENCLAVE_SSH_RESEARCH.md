# Secure Enclave SSH 조사

조사 기준일: 2026-08-11.

이 문서는 SeKey·Secretive의 관계, SSH agent와 Apple OpenSSH security-key
provider의 차이, Hacker News 토론에서 보고된 macOS/CryptoTokenKit(CTK) 제약,
그리고 같은 구현 경로를 시도한 공개 프로젝트를 조사한다. 사실 판단에는
프로젝트 소유자의 README·소스, Apple이 배포한 OpenSSH 소스와 이 저장소의
구현·실기기 기록을 우선 사용했다. HN 댓글은 경험 보고나 주장으로만 분류하며,
별도 1차 자료로 확인되지 않은 내용은 검증된 플랫폼 사실로 취급하지 않는다.

## 핵심 결론

- README에는 Secretive의 현재 표현과 같은 강도로 “`se-sshctl` was inspired
  by SeKey and Secretive.”라고 쓸 수 있다. 한국어로는 “`se-sshctl`은 SeKey와
  Secretive에서 영감을 받았다.”이다. Secretive 자신도 SeKey에서 영감을 받은
  별도 구현이라고 밝힌다.
  ([Secretive README](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/README.md#L66-L69))
- Secretive와 SeKey는 SSH agent이므로 OpenSSH가 그들의 Unix-domain socket을
  사용하도록 `IdentityAgent` 또는 `SSH_AUTH_SOCK`을 지정해야 한다.
  ([Secretive 설정 소스](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Secretive/Views/Configuration/Instructions.swift#L16-L23),
  [SeKey 설정](https://github.com/sekey/sekey/blob/869cb896da62ad43352c99a2b7d0e1baf4b00af6/README.md#L28-L42))
- `se-sshctl`의 identity file 경로는 agent가 아니라
  `/usr/lib/ssh-keychain.dylib` provider가 직접 서명한다. 따라서 별도
  `IdentityAgent`는 필요하지 않지만, `IdentityFile`과
  `SecurityKeyProvider` 설정은 필요하다.
  ([Apple OpenSSH 서명 경로](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/sshconnect2.c#L1210-L1261),
  [`se-sshctl` 설정 렌더러](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L187-L205))
- HN에서 드러난 가장 큰 운영 위험은 비내보내기 키의 기기 상실, 원격
  `authorized_keys` 회수, 여러 identity를 다룰 때의 provider 동작, 그리고
  잠금·로그아웃 등 실행 문맥이다. 현재 구현은 선택·identity file·검증·삭제의
  일부를 다루지만, 복구/배포/CA와 잠금 상태 검증까지 제공하지는 않는다.
  ([비내보내기 키의 기기 상실](https://news.ycombinator.com/item?id=46026158),
  [현재 실기기 검증 범위](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L12-L38))

## 조사 방법과 HN 전수 범위

대상 HN story `46025721`의 본문과 HTML 댓글 행 192개를 모두 읽었다. HN API의
story 레코드도 `descendants: 192`를 보고하므로, 조사 시점의 공개 댓글 트리를
빠짐없이 대조했다. 아래에는 단순 동의·농담을 반복하지 않고, 기술적 quirk,
실패 모드, 보안·운영 제약, 미검증 주장과 관련 구현 시도만 주제별로 추출했다.
([전체 HN thread](https://news.ycombinator.com/item?id=46025721),
[HN API story 레코드](https://hacker-news.firebaseio.com/v0/item/46025721.json))

## SeKey와 Secretive: inspiration 표현

Secretive의 현재 README는 `Acknowledgements` 아래 `sekey` 항목에서
“Secretive was inspired by the sekey project.”라고 쓴다. 한국어로는
“Secretive는 sekey 프로젝트에서 영감을 받았다.”이다. 현재 섹션명은
`Inspirations`가 아니다.
([현재 README](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/README.md#L66-L69))

역사적으로도 관계는 일관된다. 최초 README는 Secure Enclave SSH 키 저장이
SeKey에서 크게 영감을 받았다고 했고, 이후 README는 SeKey에서 영감을 받아
외부 의존성 없는 Swift 앱으로 다시 썼다고 설명했다. 즉 Secretive는 SeKey의
후속 별도 구현이지 같은 프로젝트나 fork라고 주장하지 않는다.
([최초 README](https://github.com/maxgoedjen/secretive/blob/45a09f25ac75d9853126ffc25681417c5c15275d/README.md),
[Swift 재작성 설명](https://github.com/maxgoedjen/secretive/blob/6dc93806a80ad807dd715ab3d15a2639633cd619/README.md))

SeKey는 자기 자신을 Secure Enclave를 사용해 UNIX/Linux SSH 서버에 인증하는
SSH agent라고 정의한다. 따라서 `se-sshctl`이 두 프로젝트 모두에서 제품·보안
방향의 영감을 받았다고 표현하는 것은 관계를 과장하지 않는다.
([SeKey README](https://github.com/sekey/sekey/blob/869cb896da62ad43352c99a2b7d0e1baf4b00af6/README.md#L10-L20))

## `IdentityAgent`가 필요한 경로와 필요 없는 경로

### Secretive

Secretive는 자체 SSH agent를 제공한다. 앱이 안내하는 기본 설정은 다음과 같다.
([Secretive 설정 소스](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Secretive/Views/Configuration/Instructions.swift#L16-L23))

```sshconfig
Host *
    IdentityAgent ~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

OpenSSH의 `IdentityAgent`는 인증 agent와 통신할 Unix-domain socket을 지정하고
`SSH_AUTH_SOCK`을 덮어쓴다. 그러므로 이 설정은 OpenSSH가 기본 agent가 아니라
Secretive에게 키 조회와 서명을 요청하게 한다.
([Apple OpenSSH `IdentityAgent`](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh_config.5#L1125-L1153))

공식 릴리스 소켓 경로는
`~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh`이다.
Secretive는 agent container home에 `socket.ssh`를 붙이고, 기본 bundle ID와
agent target bundle ID를 코드로 정의한다.
([소켓 경로 구성](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Packages/Sources/Common/URLs.swift#L6-L18),
[기본 bundle ID](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Config/Config.xcconfig#L5-L7),
[agent bundle ID](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Secretive.xcodeproj/project.pbxproj#L1538-L1546))

`IdentityAgent`만이 유일한 방법은 아니다. 같은 경로를 `SSH_AUTH_SOCK`으로
내보내고 클라이언트가 환경 변수를 존중해도 된다. Secretive FAQ와 설정 화면은
두 방법을 모두 안내한다.
([Secretive FAQ](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/FAQ.md#L7-L10),
[shell 설정](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Secretive/Views/Configuration/Instructions.swift#L47-L78))

### `se-sshctl`

`se-sshctl`은 별도 agent를 실행하지 않는다. resident identity file을
`IdentityFile`로 읽은 Apple OpenSSH가 `SecurityKeyProvider`로 지정한 dylib를
호출해 CTK identity로 서명한다. OpenSSH 설정 정의에서도 `IdentityAgent`는
agent socket, `SecurityKeyProvider`는 authenticator-hosted key의 provider라는
서로 다른 옵션이다.
([Apple OpenSSH `IdentityAgent`](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh_config.5#L1125-L1153),
[Apple OpenSSH `SecurityKeyProvider`](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh_config.5#L1872-L1880))

구현도 agent가 준 키에는 `ssh_agent_sign`을 쓰고, 그 밖의 identity file에는
`options.sk_provider`를 전달해 직접 서명하는 두 경로를 구분한다. security-key
identity에 provider가 없으면 identity를 건너뛴다.
([서명 경로](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/sshconnect2.c#L1210-L1261),
[provider 확인](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/sshconnect2.c#L1703-L1724))

현재 `config render`는 `IdentityFile`, `SecurityKeyProvider`,
`IdentitiesOnly yes`, `ForwardAgent no`를 만들고 `IdentityAgent`는 만들지 않는다.
원격 검증은 오히려 `IdentityAgent=none`으로 agent를 끄고 같은 provider와 identity file을
조합의 인증 성공을 검사한다. 따라서 “별도 `IdentityAgent` 불필요”는 설계
추론뿐 아니라 현재 검증 경로의 속성이기도 하다.
([설정 렌더러](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L187-L205),
[원격 검증 인자](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L295-L340))

## HN에서 추출한 macOS/OpenSSH/CTK 쟁점

이 절의 링크는 대부분 댓글 작성자의 경험·의견에 대한 직접 출처다. Apple의
보증된 동작으로 읽어서는 안 된다.

### CTK와 OpenSSH의 quirk·실패 모드

- `sc_auth`가 실제로는 shell script이고 비공개 CTK 도구
  `/System/Library/Frameworks/CryptoTokenKit.framework/ctkcard`를 호출한다는
  코드 관찰이 보고됐다. 이는 공개 API 계약보다 OS 구현 변화에 민감할 수 있다는
  운영 신호다.
  ([HN 보고](https://news.ycombinator.com/item?id=46029909))
- P-384 non-exportable CTK identity 생성은 가능해도 `ssh-keygen -K`가 사용할
  identity file를 내보내지 못한다는 실험이 보고됐다. OpenSSH security-key key type은
  authenticator-hosted ECDSA/Ed25519 계열이므로, `se-sshctl`이 p-256-ne만 허용하는
  현재 범위와 부합한다.
  ([HN 실험](https://news.ycombinator.com/item?id=46027069),
  [`se-sshctl` p-256-ne 제한](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L90-L112))
- `ssh-keygen -K`가 Apple provider의 dummy PIN을 요구하며,
  `KEYCHAIN_CERTIFICATES`가 resident download를 하나로 걸러주지 않아 여러
  identity가 같은 기본 파일명에 충돌한 동작은 이 프로젝트가 macOS 26.6.1
  실기기에서 재현했다. 현재 구현은 overwrite 위치별 격리 다운로드 후 SSH
  fingerprint가 일치한 identity file만 선택한다.
  ([실기기 기록](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L27-L34),
  [workaround 코드](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L89-L142))
- 여러 identity 선택 실패는 gist 댓글에서도 Apple Feedback `FB21992630`으로
  보고됐다. Feedback 본문은 공개 검증할 수 없으므로 번호와 제출 사실은 댓글
  작성자의 주장으로만 남긴다.
  ([gist 댓글](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf?permalink_comment_id=5877213))
- 공개 토론에는 최소 지원 OS가 Sequoia라는 경험과 Tahoe에서만 보였다는 경험이
  서로 충돌한다. 따라서 OS 하한은 댓글만으로 확정할 수 없다.
  ([Sequoia 동작 주장](https://news.ycombinator.com/item?id=46035493),
  [Tahoe 한정 주장](https://news.ycombinator.com/item?id=46026020),
  [추가 반례](https://news.ycombinator.com/item?id=46029938))
- Secretive가 Tahoe에서 간헐적으로 멈춘다는 보고가 있었지만 작성자는 issue를
  제출하지 않았다고 명시했다. 재현 조건과 원인은 미검증이다.
  ([HN 보고와 후속](https://news.ycombinator.com/item?id=46025938))

### 운영 제약과 복구

- non-exportable의 직접 결과는 private key를 백업·이전할 수 없다는 것이다.
  기기 손실·고장 시 identity도 잃으므로 별도 복구 키와 원격 회수 절차가
  필요하다는 지적이 반복됐다.
  ([기기 상실 지적](https://news.ycombinator.com/item?id=46026158),
  [여러 키/backup YubiKey 제안](https://news.ycombinator.com/item?id=46026177),
  [위협 모델별 절충](https://news.ycombinator.com/item?id=46028457))
- 기존 exportable key를 가져온 뒤 Secure Enclave에 넣는 방식은 원본이 이미
  존재하므로 non-exportability의 의미가 달라진다. HN에서도 이 차이가 질문과
  반론으로 드러났다.
  ([import 질문](https://news.ycombinator.com/item?id=46028253),
  [Touch ID 뒤 export 위험 주장](https://news.ycombinator.com/item?id=46026910))
- 일부 서버가 계정당 키 하나만 허용하거나 `ssh-copy-id`를 쓰는 운영에서는
  device별 키 배포와 rotation이 부담이다. SSH CA는 배포를 줄일 수 있지만 CA
  키 보호·인증서 발급·revocation/KRL이라는 별도 운영 문제가 생긴다는 논의가
  이어졌다.
  ([단일 키 제약](https://news.ycombinator.com/item?id=46028382),
  [`ssh-copy-id` 논의](https://news.ycombinator.com/item?id=46027770),
  [SSH CA와 KRL 논의](https://news.ycombinator.com/item?id=46028284))
- agent에 identity가 많이 등록되면 서버가 허용하는 인증 시도 수를 소진할 수
  있고, per-host 명시적 mapping이 필요하다는 경험이 보고됐다.
  ([HN 운영 경험](https://news.ycombinator.com/item?id=46030683),
  [Apple OpenSSH `IdentitiesOnly`](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh_config.5#L1104-L1124))
- X.509 certificate의 만료와 underlying private key의 수명은 같지 않으며,
  같은 키로 CSR을 만들고 새 certificate를 import할 수 있다는 설명이 있었다.
  이 저장소는 certificate validity를 inventory로 읽지만 갱신 workflow는 아직
  제공하지 않으므로, 실제 갱신 동작은 별도 검증 대상이다.
  ([HN 설명](https://news.ycombinator.com/item?id=46031036),
  [현재 metadata matching](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L198-L205))
- iCloud sync나 passkey provider로 동기화할 수 있다는 아이디어도 나왔지만,
  origin binding 등 SSH와 맞지 않는 차이가 있으며 구현·보안 속성은 검증되지
  않은 제안이다.
  ([HN 제안](https://news.ycombinator.com/item?id=46026785))

### 보안 우려와 UX 제약

- `-t none`은 export를 막지만 per-use LocalAuthentication을 제거한다. 같은 사용자
  문맥의 malware가 서명을 요청할 수 있다는 점은 현재 threat model도 명시하며,
  `none` 생성에는 명시적 승인 flag를 요구한다.
  ([현재 threat model](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L25-L36),
  [생성 gate](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L90-L112))
- `bio`는 매번 사용자 승인을 요구할 수 있어 SSH multiplexing, Git signing,
  rebase처럼 서명이 잦은 작업에서 불편하다는 경험이 있다. notification-only나
  짧은 grace window 제안은 UX 아이디어이지 현재 CTK 보안 속성이 아니다.
  ([HN 경험](https://news.ycombinator.com/item?id=46051903))
- macOS에 별도 secure desktop이 없으므로 악성 앱이 생체인증 prompt와 타이밍을
  속이거나 사용자를 반복 prompt에 익숙하게 만들 수 있다는 우려가 제기됐다.
  HN의 공격 가능성 평가는 실증되지 않았지만, prompt가 요청 주체와 작업 내용을
  충분히 구별해 주는지는 OS UX라는 residual risk다.
  ([prompt spoofing 우려](https://news.ycombinator.com/item?id=46029015),
  [반복 prompt 습관화](https://news.ycombinator.com/item?id=46028201),
  [secure desktop 논의](https://news.ycombinator.com/item?id=46031461))
- OpenSSH agent의 per-use confirmation도 존재하지만, local과 forwarded 요청을
  사용자에게 명확히 구분해 주지 못한다는 비판이 있었다. `se-sshctl`은 agent
  forwarding을 기본 차단해 이 문제의 범위를 줄이지만 OS prompt 자체를 개선하지
  않는다.
  ([HN agent confirmation 논의](https://news.ycombinator.com/item?id=46028657),
  [현재 설정 렌더러](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L187-L205))
- identity file에는 private key가 없다는 설명과 함께, identity file가 identity handle이라서
  분실·노출의 기밀성보다 잘못된 키 선택과 가용성 문제가 중요하다는 논의가
  있었다. 정확한 CTK 내부 참조 수명에 관한 댓글의 추측은 검증되지 않았다.
  ([HN 논의](https://news.ycombinator.com/item?id=46028626),
  [OpenSSH resident identity file 생성 정의](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh-keygen.1#L391-L399))
- P-256/NIST curve만 현실적으로 쓰는 경로에 대한 불신과 EdDSA fault attack을
  둘러싼 반론이 있었다. 이 암호학 논쟁은 HN 주장만으로 결론내릴 수 없고,
  현재 프로젝트는 Apple provider와 OpenSSH가 실제 연동되는 p-256-ne만 목표로
  한다.
  ([NIST curve 우려](https://news.ycombinator.com/item?id=46027101),
  [EdDSA 반론](https://news.ycombinator.com/item?id=46027225),
  [추가 논쟁](https://news.ycombinator.com/item?id=46027799))
- file key passphrase는 file 탈취 후 offline brute force 대상이고, 빈 passphrase는
  더 약하다는 지적도 있었다. 이는 Secure Enclave identity의 private key가
  non-exportable인 모델과 비교하는 위협 모델 설명이지 CTK 동작의 증거는 아니다.
  ([HN 논의](https://news.ycombinator.com/item?id=46026045),
  [offline brute force 설명](https://news.ycombinator.com/item?id=46026192),
  [빈 passphrase 위험](https://news.ycombinator.com/item?id=46026144))

## `se-sshctl`이 다루는 것과 아직 다루지 않는 것

| 쟁점 | 현재 상태 | 직접 근거 |
| --- | --- | --- |
| identity 생성·목록·정확한 선택 | 다룸. `p-256-ne`, `bio`/`none`, pre/post diff, 엄격한 parser와 ambiguous metadata 거부 | [생성 코드](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L81-L127), [trust boundary](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L13-L23) |
| 다중 identity의 identity-file 충돌 | 다룸. 격리된 overwrite 순회와 SSH fingerprint 일치로 선택 | [설치 코드](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L89-L142), [실기기 기록](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L27-L34) |
| shell·provider trust boundary | 다룸. 고정 절대 실행 파일과 argument array, provider signature·identifier·Apple anchor 검사 | [threat model](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L13-L23), [provider 검사](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L388-L397) |
| agent 없는 per-host SSH 설정 | 다룸. provider와 identity file, `IdentitiesOnly yes`, `ForwardAgent no`; global profile을 바꾸지 않음 | [설정 렌더러](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L187-L205) |
| local·remote 검증 | 다룸. local sign/verify와 agent를 끈 remote 인증; unlocked GUI session의 SSH 안에서도 실기기 검증 | [원격 검증](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L295-L340), [실기기 범위](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L12-L25) |
| 안전한 delete | 부분적으로 다룸. CTK SHA-256 exact hash 확인, 내부 SHA-1 해석, 두 형식의 post-delete 검증은 제공하지만 원격 authorization 회수·recovery 상태는 자동 입증하지 못함 | [삭제 코드](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L130-L195), [residual risk](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L40-L47) |
| `none` signing 위험 | 다룸. 사용자 승인과 문서화는 있으나 malware의 signing 요청이라는 본질적 위험은 남음 | [생성 gate](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L90-L112), [의미](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L25-L36) |
| `bio`와 세션 문맥 | 미검증. locked console, logout, reboot 후 first unlock 전, launchd도 미검증 | [명시된 한계](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L36-L38) |
| OS 최소 버전·system tool drift | 부분적. macOS 26.6.1은 검증했고 provider 서명은 검사하나, Sequoia/Tahoe 하한과 향후 `sc_auth` 출력·내부 도구 변화는 미확정 | [검증 환경](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L3-L10), [HN 상충 보고](https://news.ycombinator.com/item?id=46035493) |
| backup·migration·iCloud sync | 제공하지 않음. non-exportable identity와 독립 break-glass key를 전제로 함 | [현재 threat model](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L25-L36), [HN 기기 상실 지적](https://news.ycombinator.com/item?id=46026158) |
| 원격 배포·SSH CA·KRL | 제공하지 않음. 로컬 identity 삭제 전에 외부 회수를 사용자가 수행해야 함 | [삭제 경계](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L130-L195), [HN CA/KRL 논의](https://news.ycombinator.com/item?id=46028284) |
| X.509 갱신·만료 workflow | 제공하지 않음. metadata는 읽지만 CSR·certificate re-import를 관리하지 않음 | [현재 metadata 사용](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/LifecycleCommands.swift#L198-L205), [HN 갱신 설명](https://news.ycombinator.com/item?id=46031036) |
| Touch ID prompt 신뢰·grace window | 제공하지 않음. OS UX의 residual risk이며 `bio` 실기기 검증도 남아 있음 | [HN prompt 우려](https://news.ycombinator.com/item?id=46029015), [검증 한계](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/THREAT_MODEL.md#L49-L55) |

## 같은 Apple CTK + OpenSSH provider 경로의 공개 시도

Secretive·SeKey처럼 별도 agent를 만드는 프로젝트와 달리, 아래는
`sc_auth`로 CTK identity를 만들고 Apple `ssh-keychain.dylib`를 OpenSSH
security-key provider로 쓰는 동일 계열이다.

| 프로젝트 | 구현 범위 | `se-sshctl`과의 차이 | 직접 근거 |
| --- | --- | --- | --- |
| arianvp gist | 생성·목록·삭제, `ssh-keygen -K`, dummy PIN, identity file과 agent/global `SSH_SK_PROVIDER` 사용을 설명한 최초 공개 recipe에 가깝다 | 수동 절차이며 stable identity file 선택, strict parsing, provider trust 검사, 격리 remote verify와 post-delete 검증이 없다 | [gist 본문](https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf) |
| `cavoirom/sekey-sh` | `sc_auth`로 `p-256-ne bio` 생성·목록·삭제·public key 추출을 하고 identity들을 agent에 추가한다 | shell/agent 중심이다. 여러 download 충돌을 다루지만 per-host identity file 관리, 격리 검증, SHA-256-selected 삭제는 제공하지 않는다 | [README](https://github.com/cavoirom/sekey-sh/blob/master/README.md), [script](https://github.com/cavoirom/sekey-sh/blob/master/sekey.sh) |
| `fyezool/ssh-apple-secure-enclave` | SwiftUI 앱으로 생성·목록·삭제·import/export와 `ssh-keygen`/`ssh-add` 통합을 제공한다 | GUI·agent/global 환경 설정 중심이며 P-384/P-521 identity file 제한과 Process/GUI-session 우회를 자체 코드에서 처리한다. README의 최소 OS 주장은 상충하므로 플랫폼 사실로 채택하지 않는다 | [README 기능](https://github.com/fyezool/ssh-apple-secure-enclave/blob/1586d30299219429ea630f98ff33457be6b79d75/README.md#L103-L115), [제약](https://github.com/fyezool/ssh-apple-secure-enclave/blob/1586d30299219429ea630f98ff33457be6b79d75/README.md#L208-L221), [서비스 코드](https://github.com/fyezool/ssh-apple-secure-enclave/blob/1586d30299219429ea630f98ff33457be6b79d75/SecureEnclaveSSH/Services/SCAuthService.swift#L130-L245) |
| `whitworth-org/pinentry-darwin` | `p256-ne bio`를 만들고 Apple provider로 `ssh-add`에 넣는다 | pinentry 앱의 부가 SSH identity 기능이며 agent 중심이다. stable identity file·검증·삭제 관리 도구는 아니다 | [README](https://github.com/whitworth-org/pinentry-darwin/blob/2e52c88963be96404c80232407c5632fb635264f/README.md#L36-L46), [`ssh-add` 호출](https://github.com/whitworth-org/pinentry-darwin/blob/2e52c88963be96404c80232407c5632fb635264f/Sources/SSHIdentity/SSHAddClient.swift#L4-L11) |
| `o-az/shussh` | demo CLI로 `sc_auth` 생성·목록과 global provider 설정을 시도한다 | 코드가 label/hash 출력 수준이고 identity file 선택·삭제·서명·remote 검증이 없다 | [identity 코드](https://github.com/o-az/shussh/blob/7fc7e187b62fcbd973d9a8dcd94db445fa0dc5db/bin/keys.ts#L22-L75), [provider 설정](https://github.com/o-az/shussh/blob/7fc7e187b62fcbd973d9a8dcd94db445fa0dc5db/bin/cli.ts#L315-L350) |
| `lstoll/keychain` | Go에서 Keychain/CTK identity 생성·삭제·CSR을 다루는 일반 library다 | CTK 인접 구현이지만 OpenSSH provider, identity file, SSH 검증 도구는 아니다 | [CTK identity 코드](https://github.com/lstoll/keychain/blob/928e30adc4106c62d2edd144141f7bb997a9b1e5/ctk_identity.go#L15-L112) |

공개 코드 조사 범위에서는 `se-sshctl`과 같이 identity lifecycle, collision-safe
stable identity file 설치, provider 신뢰 검사, agent를 차단한 local/remote 검증,
SHA-256-selected 삭제와 원격 authorization·recovery 경계를 함께 제공하는 CLI는 찾지 못했다. 이는
조사한 공개 저장소에 한정한 부재 관찰이지 전 세계 구현의 부재 증명은 아니다.

## HN에서 언급된 인접 프로젝트

아래는 동일 CTK-provider 경로의 직접 경쟁 구현이 아니라 대안 기술·UX다.

- Secretive와 SeKey는 Secure Enclave를 agent protocol 뒤에 둔다.
  ([Secretive README](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/README.md),
  [SeKey README](https://github.com/sekey/sekey/blob/869cb896da62ad43352c99a2b7d0e1baf4b00af6/README.md))
- KeyMux는 Secure Enclave key를 SSH·SSL·PGP에 쓰는 macOS 앱으로 언급됐다.
  ([HN 언급](https://news.ycombinator.com/item?id=46026359),
  [KeyMux 공식 사이트](https://keymux.com/))
- Facebook의 `sks`, `ssh-tpm-agent`, Keeta agent는 Secure Enclave 대신 각각
  다른 hardware-backed/TPM 또는 agent 접근을 취하는 인접 구현이다.
  ([sks](https://github.com/facebookincubator/sks),
  [ssh-tpm-agent](https://github.com/Foxboron/ssh-tpm-agent),
  [Keeta agent HN 설명](https://news.ycombinator.com/item?id=46028517),
  [Keeta agent 저장소](https://github.com/KeetaNetwork/agent))
- 1Password·Bitwarden, YubiKey, Krypton과 WebAuthn toy도 대안으로 논의됐지만
  Apple CTK identity file을 직접 관리하는 구현은 아니다.
  ([1Password·Bitwarden 논의](https://news.ycombinator.com/item?id=46030683),
  [YubiKey 논의](https://news.ycombinator.com/item?id=46026399),
  [Krypton 운영 경험](https://news.ycombinator.com/item?id=46036352),
  [WebAuthn toy](https://news.ycombinator.com/item?id=46026785))

## 전제와 남은 불확실성

- `IdentityAgent`가 불필요하다는 결론은 `se-sshctl install`이 만든
  resident identity file과 `SecurityKeyProvider /usr/lib/ssh-keychain.dylib`를
  사용한다는 전제다. identity file과 provider 설정까지 불필요하다는 뜻은 아니다.
  ([설정 렌더러](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L187-L205))
- 일반 연결에서 `IdentityAgent none`은 필수값이 아니다. 격리 검증에서는 다른
  agent를 확실히 배제하기 위해 사용한다. 일반 설정은 `IdentitiesOnly yes`로
  명시한 identity 범위를 제한한다.
  ([Apple OpenSSH `IdentitiesOnly`](https://github.com/apple-oss-distributions/OpenSSH/blob/f386b2e948280f6ecac875329c0b56020821d558/openssh/ssh_config.5#L1104-L1124),
  [격리 검증](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/Sources/SSHCTLCore/OperationalCommands.swift#L316-L338))
- Secretive socket 경로는 공식 release build 기준이다. custom bundle ID나 debug
  build는 container나 socket 이름이 달라질 수 있다.
  ([build별 socket 이름](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Packages/Sources/Common/URLs.swift#L12-L17),
  [bundle ID override](https://github.com/maxgoedjen/secretive/blob/b00328674542c42c35058069122fd6e63ce2ffb4/Sources/Config/Config.xcconfig#L5-L7))
- 현재 물리 Mac 증거는 macOS 26.6.1의 `p-256-ne + none`, unlocked GUI session과
  그 안의 SSH session까지다. `bio`, console lock/logout, first unlock 전,
  launchd 동작은 결론을 유보한다.
  ([실기기 검증 한계](https://github.com/ajchemist/se-sshctl/blob/27dde4f2f013de7f0268d36d5572c6f17efa0746/docs/HARDWARE_VERIFICATION.md#L36-L38))
- HN의 prompt spoofing, Secretive lockup, OS 최소 버전, 알고리즘 안전성 주장은
  재현·vendor 문서·공개 issue가 부족하거나 상충한다. 이 문서는 추적할 위험으로
  보존할 뿐 검증된 결함으로 판정하지 않는다.
  ([prompt 주장](https://news.ycombinator.com/item?id=46029015),
  [lockup 주장](https://news.ycombinator.com/item?id=46025938),
  [OS 상충 주장](https://news.ycombinator.com/item?id=46035493),
  [알고리즘 논쟁](https://news.ycombinator.com/item?id=46027101))
