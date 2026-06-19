import type { Metadata } from 'next';
import { JetBrains_Mono } from 'next/font/google';
import './globals.css';

const mono = JetBrains_Mono({ subsets: ['latin'], variable: '--font-jb', display: 'swap', weight: ['400', '500', '700'] });

export const metadata: Metadata = {
  title: 'argus - url & file threat scanner',
  description: 'Paste a link or drop a file for a Safe / Suspicious / Malicious verdict. Hostile input is never opened.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={mono.variable}>
      <body>
        <div className="crt" aria-hidden />
        <div className="frame" aria-hidden />
        {children}
      </body>
    </html>
  );
}
