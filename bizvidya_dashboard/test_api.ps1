Write-Host "🚀 COMPREHENSIVE API TESTING" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Yellow

$token = $null
$headers = @{}

function Test-Endpoint {
    param($Name, $Method, $Endpoint, $Body = $null)
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri "http://localhost:5000$Endpoint" -Method GET -Headers $headers
        } elseif ($Method -eq "POST") {
            $response = Invoke-RestMethod -Uri "http://localhost:5000$Endpoint" -Method POST -Body $Body -ContentType "application/json" -Headers $headers
        }
        Write-Host "✅ $Name" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "❌ $Name - Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Test 1: Health Check
Write-Host "`n1. BASIC CONNECTIVITY" -ForegroundColor Yellow
Test-Endpoint -Name "Health Check" -Method "GET" -Endpoint "/api/health"

# Test 2: Authentication
Write-Host "`n2. AUTHENTICATION" -ForegroundColor Yellow
try {
    $loginData = @{ email = "admin@university.edu"; password = "admin123" } | ConvertTo-Json
    $auth = Invoke-RestMethod -Uri "http://localhost:5000/api/auth/login" -Method POST -Body $loginData -ContentType "application/json"
    $token = $auth.access_token
    $headers = @{ "Authorization" = "Bearer $token" }
    Write-Host "✅ Login Successful" -ForegroundColor Green
} catch {
    Write-Host "❌ Login Failed" -ForegroundColor Red
    exit
}

# Test 3: Dashboard & Analytics
Write-Host "`n3. DASHBOARD & ANALYTICS" -ForegroundColor Yellow
Test-Endpoint -Name "Dashboard Overview" -Method "GET" -Endpoint "/api/dashboard/overview"
Test-Endpoint -Name "Performance Analytics" -Method "GET" -Endpoint "/api/dashboard/analytics/performance"

# Test 4: Student Management
Write-Host "`n4. STUDENT MANAGEMENT" -ForegroundColor Yellow
Test-Endpoint -Name "List Students" -Method "GET" -Endpoint "/api/students"
Test-Endpoint -Name "At-Risk Students" -Method "GET" -Endpoint "/api/students/at-risk"

# Test 5: Faculty Management  
Write-Host "`n5. FACULTY MANAGEMENT" -ForegroundColor Yellow
Test-Endpoint -Name "List Faculty" -Method "GET" -Endpoint "/api/faculty"

# Test 6: Financial Management
Write-Host "`n6. FINANCIAL MANAGEMENT" -ForegroundColor Yellow
Test-Endpoint -Name "Financial Summary" -Method "GET" -Endpoint "/api/finance/summary"

Write-Host "`n==========================================" -ForegroundColor Yellow
Write-Host "🎉 TESTING COMPLETE!" -ForegroundColor Green