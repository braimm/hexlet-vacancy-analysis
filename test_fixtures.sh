curl -X POST http://127.0.0.1:8000/auth/register/ \
  -H "Content-Type: application/json" \
  -d '{
        "email": "t214441est1212@example.com",
        "password": "Qwerty123",
        "passwordAgain": "Qwerty123",
        "acceptTerms": true
      }'
