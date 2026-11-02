import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function defangString(str: string): string {
  if (!str) return '';
  return str
    .replace(/https:\/\//gi, 'hxxps://')
    .replace(/http:\/\//gi, 'hxxp://')
    .replace(/ftp:\/\//gi, 'fxp://')
    .replace(/\./g, '[.]')
    .replace(/@/g, '[@]');
}

export function refangString(str: string): string {
  if (!str) return '';
  return str
    .replace(/hxxps:\/\//gi, 'https://')
    .replace(/hxxp:\/\//gi, 'http://')
    .replace(/fxp:\/\//gi, 'ftp://')
    .replace(/\[\.\]/g, '.')
    .replace(/\[@\]/g, '@');
}

export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    } else {
      const textArea = document.createElement('textarea');
      textArea.value = text;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();
      document.execCommand('copy');
      textArea.remove();
      return true;
    }
  } catch (err) {
    console.error('Failed to copy to clipboard:', err);
    return false;
  }
}

export function formatDate(dateStr?: string): string {
  if (!dateStr) return 'N/A';
  try {
    const d = new Date(dateStr);
    return d.toLocaleString('en-IN', {
      timeZone: 'UTC',
      dateStyle: 'medium',
      timeStyle: 'medium',
    }) + ' UTC';
  } catch {
    return dateStr;
  }
}

export async function computeClientSha256(file: File): Promise<string> {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

