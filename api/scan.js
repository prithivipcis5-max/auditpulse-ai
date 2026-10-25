import { GoogleGenAI } from '@google/genai';
import dns from 'node:dns/promises';

export default async function handler(req, res) {
  // 1. Enable CORS & Method check
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }

  // Clean domain string
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();

  try {
    // 2. Perform Real Live DNS Checks
    let mxRecords = [];
    let txtRecords = [];
    let hasSpf = false;
    let hasDmarc = false;

    try {
      mxRecords = await dns.resolveMx(cleanDomain);
    } catch (e) {
      /* No MX found */
    }

    try {
      txtRecords = await dns.resolveTxt(cleanDomain);
      const flattenedTxt = txtRecords.flat().join(' ');
      hasSpf = flattenedTxt.includes('v=spf1');
    } catch (e) {
      /* No TXT found */
    }

    try {
      const dmarcRecords = await dns.resolveTxt(`_dmarc.${cleanDomain}`);
      hasDmarc = dmarcRecords.flat().join(' ').includes('v=DMARC1');
    } catch (e) {
      /* No DMARC found */
    }

    // 3. Call Gemini AI Engine
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'GEMINI_API_KEY missing in Vercel Environment Variables' });
    }

    const ai = new GoogleGenAI({ apiKey });

    const auditData = `
    Target Domain: ${cleanDomain}
    MX Mail Servers: ${mxRecords.length > 0 ? 'Configured' : 'Missing'}
    SPF Email Spoof Protection: ${hasSpf ? 'Configured' : 'MISSING / UNPROTECTED'}
    DMARC Email Security: ${hasDmarc ? 'Configured' : 'MISSING / UNPROTECTED'}
    `;

    const prompt = `
    You are AuditPulse AI, a sharp, witty cybersecurity compliance auditor.
    Analyze these REAL technical findings for "${cleanDomain}":
    ${auditData}

    Return ONLY a JSON object (no markdown, no backticks) with this structure:
    {
      "domain": "${cleanDomain}",
      "score": <number between 15 and 85 based on findings>,
      "riskLevel": "<CRITICAL RISK | HIGH RISK | MODERATE RISK>",
      "roast": "<A hilarious, sharp 2-sentence roast of their security posture based on these real findings>",
      "vulnerabilities": [
        { "title": "<Technical Issue>", "severity": "<Critical|High|Medium>", "fix": "<Remediation step or CLI command>" }
      ]
    }
    `;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
    });

    const rawText = response.text.replace(/```json|```/g, '').trim();
    const result = JSON.parse(rawText);

    return res.status(200).json(result);

  } catch (error) {
    console.error('Scan Error:', error);
    return res.status(500).json({ error: 'Scan failed. Ensure GEMINI_API_KEY is set correctly.' });
  }
}
