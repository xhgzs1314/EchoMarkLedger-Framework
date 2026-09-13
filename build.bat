@echo off
REM
echo ========================================
echo EchoMarkLedger - build
echo ========================================
call npm run build
if errorlevel 1 (
  echo.
  echo 构建失败。若是首次使用，请先执行: npm install
  exit /b 1
)
echo.
echo 运行回归测试: npm test
