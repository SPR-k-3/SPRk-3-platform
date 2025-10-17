#!/bin/bash

echo "🔬 Quick Real-World Validation"
echo "================================"

# Test 1: A small Python ML project
echo -e "\n📦 Test 1: Small ML Project"
git clone --depth 1 https://github.com/ageitgey/face_recognition.git test_face_rec 2>/dev/null
python sprk3_engine.py test_face_rec

# Test 2: A web framework (Flask)
echo -e "\n📦 Test 2: Web Framework"
git clone --depth 1 https://github.com/pallets/flask.git test_flask 2>/dev/null
python sprk3_engine.py test_flask

# Test 3: Your own repository
echo -e "\n📦 Test 3: SPR{K}3 Repository (self-test)"
python sprk3_engine.py .

# Clean up
rm -rf test_face_rec test_flask

echo -e "\n✅ Validation Complete!"
