import type { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';

const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jb', display: 'swap', weight: ['400', '500', '700'] });

export const metadata: Metadata = {
  metadataBase: new URL(process.env.ARGUS_PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'https://argus.onrender.com'),
  title: 'argus - url & file threat scanner',
  description: 'Paste a link or drop a file for a Safe / Suspicious / Malicious verdict. Hostile input is never opened.',
  openGraph: {
    title: 'argus - url & file threat scanner',
    description: 'Paste a link or drop a file for a Safe / Suspicious / Malicious verdict. Hostile input is never opened.',
    type: 'website',
    images: [{ url: '/argus-thumbnail.jpg', width: 1600, height: 900, alt: 'Argus URL and file scanner' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'argus - url & file threat scanner',
    description: 'Paste a link or drop a file for a Safe / Suspicious / Malicious verdict. Hostile input is never opened.',
    images: ['/argus-thumbnail.jpg'],
  },
  icons: {
    icon: '/icon.png',
    shortcut: '/icon.png',
    apple: '/apple-icon.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={mono.variable}>
      <body>
        <div className="frame" aria-hidden />
        {children}
      </body>
    </html>
  );
}
