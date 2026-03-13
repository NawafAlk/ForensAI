# ForensAI - AI Features Setup Guide

## Overview

ForensAI includes AI-powered forensic analysis capabilities:

- **Explain Artifacts**: Get AI explanations for files, registry keys, and carved data
- **Overwriting Stories**: AI-generated narratives for deleted/overwritten files
- **Risk Scoring**: Intelligent prioritization of suspicious artifacts
- **Investigator Notes**: Save AI explanations as notes for your reports

## Requirements

ForensAI uses **Groq API** for fast cloud AI inference with Llama 3.3 70B model.

### 1. Get a Groq API Key

1. Go to: https://console.groq.com
2. Sign up for a free account
3. Navigate to API Keys section
4. Create a new API key
5. Copy the key (starts with `gsk_...`)

### 2. Configure ForensAI

1. Open ForensAI
2. Go to **Options > API Keys**
3. Paste your Groq API key in the "Groq" field
4. Click Save

### 3. Test in ForensAI

1. Load an evidence image (File > Add Evidence File)
2. Select any file in the file listing
3. Go to the **File Metadata** tab
4. Click the **AI Explain This Artifact** button

If everything is set up correctly, you'll see an AI-generated explanation of the file's forensic significance.

## Usage

### Explaining Artifacts

**File Metadata Tab:**
1. Select any file
2. Switch to "File Metadata" tab
3. Click "AI Explain This Artifact"
4. Review AI explanation
5. Edit if needed
6. Click "Save as Note" to include in reports

The AI analyzes:
- File name and path
- File type and MIME type
- Timestamps (created, modified, accessed)
- File size
- MD5/SHA256 hashes

### Saved Notes

Notes are stored in `data/notes.db` and automatically included when you generate forensic reports.

## Troubleshooting

### "Groq AI service is not available"

**Check your API key:**
1. Go to Options > API Keys
2. Verify your Groq API key is entered correctly
3. Ensure the key starts with `gsk_`

**Check your internet connection:**
- Groq API requires internet access
- Verify you can reach https://api.groq.com

### Slow responses

Groq is typically very fast (1-3 seconds). If experiencing slowness:
- Check your internet connection
- The service may be experiencing high load

### Rate limits

Free Groq accounts have rate limits. If you hit limits:
- Wait a minute and try again
- Consider upgrading your Groq account for higher limits

## Available Models

ForensAI uses these Groq models:
- **llama-3.3-70b-versatile** (Default) - Best quality
- **llama-3.1-8b-instant** - Fastest responses
- **mixtral-8x7b-32768** - Balanced option

## Security Notes

- **API Key Storage**: Keys are stored locally in `config.ini`
- **Data Sent**: Only artifact metadata is sent for analysis (not file contents)
- **HTTPS**: All API communication is encrypted

## Need Help?

- Groq Documentation: https://console.groq.com/docs
- ForensAI Issues: https://github.com/your-repo/ForensAI/issues

---

**Enjoy AI-powered forensic analysis!**
