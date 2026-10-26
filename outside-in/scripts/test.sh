#!/bin/zsh
set -euo pipefail
cd "${0:A:h:h}"
mkdir -p .build/core-tests
swiftc Sources/OutsideIn/Models.swift Sources/OutsideIn/DNSCollector.swift Sources/OutsideIn/Scanners.swift Tests/CoreTests.swift -o .build/core-tests/run
.build/core-tests/run
