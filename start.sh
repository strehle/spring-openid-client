#!/bin/bash

./gradlew build
echo ""
echo ""
echo ""
echo "start browser on http://localhost:7000"
echo ""
echo ""
java -jar $(find . -name springdemo-0.0.1-SNAPSHOT.jar)
echo ""
echo ""
echo "... exit"
echo ""
