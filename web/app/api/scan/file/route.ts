import { proxyJson } from '@/lib/server-api';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  let form: FormData;
  try {
    form = await req.formData();
  } catch {
    return Response.json({ error: 'bad_request', message: 'Expected multipart form-data.' }, { status: 400 });
  }
  const file = form.get('file');
  if (!(file instanceof File)) {
    return Response.json({ error: 'bad_request', message: 'No file in the "file" field.' }, { status: 400 });
  }
  const fd = new FormData();
  fd.append('file', file, file.name || 'upload.bin');

  const qs = new URL(req.url).searchParams.toString();
  return proxyJson(`/api/scan/file${qs ? `?${qs}` : ''}`, { method: 'POST', body: fd });
}
