# NVIDIA Setup Guide

How to set up an NVIDIA account and run the SecOps Runtime with real
LLM inference instead of mock responses.

---

## 1. Create an NVIDIA Account

1. Go to **https://build.nvidia.com**
2. Click **Sign In** (top right)
3. Create an account if you don't have one — free, just needs an email
4. Verify your email and sign in

## 2. Get an API Key

1. Once signed in, browse the model catalog at https://build.nvidia.com/models
2. Click any model that has a chat playground and a **"Get API Key"** button
   (any instruct/chat model with a free API endpoint)
3. In the API playground panel on the right, click **"Get API Key"** or the key icon
4. Click **"Generate Key"**
5. Copy the key — it starts with `nvapi-...`

The free tier gives you 1,000 credits. One full incident response flow
(investigate + plan + remediate) uses roughly 3-5 credits.

## 3. Configure the Key

Copy the `.env.example` and add your key:

```bash
cp .env.example .env
```

Edit `.env`:

```bash
NVIDIA_API_KEY=nvapi-your-key-here
NVIDIA_MODEL=meta/llama-3.1-8b-instruct
NVIDIA_API_BASE=https://integrate.api.nvidia.com/v1
```

The `.env` file is gitignored and auto-loaded by all dev scripts. The API
key is account-wide — it works across all models on build.nvidia.com, so
you can get it from any model page that offers "Get API Key".
