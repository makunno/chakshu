#!/bin/bash

# Check health of all 10 backend workers

echo "Checking health of all 10 backend workers..."
echo "=============================================="
echo ""

healthy_count=0
unhealthy_count=0
total=10

for i in {1..10}; do
  echo -n "Worker $i (siem-worker-$i.tanubhavj.workers.dev): "
  
  response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
    "https://siem-worker-$i.tanubhavj.workers.dev/" 2>&1)
  
  if [ "$response" = "200" ]; then
    echo "✅ HEALTHY (HTTP 200)"
    healthy_count=$((healthy_count + 1))
  elif [ "$response" = "000" ]; then
    echo "❌ UNREACHABLE (Connection failed)"
    unhealthy_count=$((unhealthy_count + 1))
  else
    echo "❌ UNHEALTHY (HTTP $response)"
    unhealthy_count=$((unhealthy_count + 1))
  fi
done

echo ""
echo "=============================================="
echo "Summary:"
echo "  Healthy:   $healthy_count / $total"
echo "  Unhealthy: $unhealthy_count / $total"
echo ""

if [ $healthy_count -eq 0 ]; then
  echo "⚠️  WARNING: No healthy workers available!"
  echo "   Master worker will return 503 errors."
  echo ""
  echo "To fix this, redeploy the workers:"
  echo "  cd siem-tool/backend"
  echo "  for i in {1..10}; do wrangler deploy --name siem-worker-\$i; done"
elif [ $healthy_count -lt 5 ]; then
  echo "⚠️  WARNING: Less than 50% of workers are healthy."
  echo "   Consider redeploying unhealthy workers."
fi
