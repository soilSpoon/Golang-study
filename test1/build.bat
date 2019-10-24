@echo off
        IF EXIST awesome.dll DEL /F awesome.dll
        IF EXIST awesome.h DEL /F awesome.h
        SETLOCAL ENABLEDELAYEDEXPANSION
        FOR /F "tokens=* USEBACKQ" %%F IN (`go build -o awesome.dll -buildmode=c-shared main.go`) DO (
          ECHO %%F
        )
        ENDLOCAL