import { NextResponse } from 'next/server';

export async function GET() {
  // TODO: Fetch your recent detected attacks from your database or backend
  const recentAttacks = [
    {
      id: '1',
      title: 'High Severity Attack Detected: SQL Injection',
      description: 'An incoming SQL injection payload was blocked on /api/login.',
      pubDate: new Date().toUTCString(),
      link: 'https://yourdomain.com/dashboard/security',
    },
  ];

  const rssItems = recentAttacks
    .map(
      (attack) => `
    <item>
      <title><![CDATA[${attack.title}]]></title>
      <description><![CDATA[${attack.description}]]></description>
      <link>${attack.link}</link>
      <guid>${attack.id}</guid>
      <pubDate>${attack.pubDate}</pubDate>
    </item>
  `
    )
    .join('');

  const rssXml = `<?xml version="1.0" encoding="UTF-8" ?>
    <rss version="2.0">
      <channel>
        <title>AI Dashboard Security Alerts</title>
        <link>https://yourdomain.com</link>
        <description>Real-time attack notifications from your AI dashboard</description>
        <language>en-us</language>
        ${rssItems}
      </channel>
    </rss>`;

  return new NextResponse(rssXml, {
    headers: {
      'Content-Type': 'application/xml; charset=utf-8',
    },
  });
}