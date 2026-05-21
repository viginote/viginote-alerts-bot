#!/bin/bash
# VigiNote Combined Service — runs API + bot together
uvicorn api:app --host 0.0.0.0 --port ${PORT:-10000} &
python main.py
