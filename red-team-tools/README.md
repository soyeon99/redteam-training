#  RED TEAM Tools

침투 테스트 및 취약점 분석 도구 모음

##  구조
red-team-tools/
├── port_scanner/          # 포트 스캐닝 도구    소연
├── api_discovery/         # API 탐지 도구      수환
└── vulnerability_test/    # 취약점 테스트 도구  혜린


##  사용법

### 1. 포트 스캐너
python3 port_scanner/port_scan.py
python3 port_scanner/service_detector.py

## 테스트 완료 타겟:

### 내부:
- localhost:80 (DVWA)
- localhost:3000 (Juice Shop)
- localhost:8081 (Shadow API)

### 외부:
- scanme.nmap.org ✅
- httpbin.org ✅
- 13.54.249.195 (Blue Team) ✅ (웹 서버는 확인 불가)

### 발견 성과:
- 총 20개 포트 스캔
- 7개 웹 서비스 탐지
- 다양한 기술 스택 식별
  - Apache, Nginx, Gunicorn
  - PHP, Python, Node.js
  - jQuery, React, Swagger