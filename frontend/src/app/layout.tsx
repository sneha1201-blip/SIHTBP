import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AICTE Cyber Security Cell | Email Threat Detection & Forensic Intelligence Platform',
  description: 'Smart India Hackathon (SIH ID: 26106) - AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          rel="stylesheet"
          href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
          integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY="
          crossOrigin=""
        />
      </head>
      <body className="bg-cyber-dark text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}

