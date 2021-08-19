## RSA-Algorithm-Implementation

확장 유클리드 + 밀러라빈 소수판별 + 모듈러 제곱(분할정복)으로 RSA 암/복호화 알고리즘 구현하기 😉

#### 구현 단계

-   [x] BOB10_RSA 구조체 정의
-   [x] BOB10_RSA 함수들 내부 구현
-   [x] XEuclid 알고리즘 구현
-   [x] Modular Exponential 함수 구현
-   [x] Miller-rabin 소수판별 알고리즘 구현
-   [x] `GenProbPrime()` (특정 길이 소수 구해주는 함수) 관련해서 `BN_rand()`함수와 함께 Miller-rabin 함수 적용
-   [x] RSA Encryption + RSA Decryption 구현
-   [x] 메모리 할당 및 해제 체크
-   [x] 테스트 케이스 10회, 발견된 버그 수정

### 사용 방법

```sh
$ git clone https://github.com/VYWL/RSA-Algorithm-Implementation
$ cd RSA-Algorithm-Implementation
$ gcc -g -o rsa rsa.c -lssl -lcrypto
$ # 반드시 openssl이 설치되어 있어야 함!
```

### 기타사항

-   문제 있을시 연락.
