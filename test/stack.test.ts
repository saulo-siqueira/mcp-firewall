import { describe, expect, it } from 'vitest';
import { z } from 'zod';

describe('MVP stack smoke checks', () => {
  it('validates MCP request contracts with Zod', () => {
    const request = z.object({ method: z.string(), params: z.record(z.string(), z.unknown()).optional() });
    expect(request.parse({ method: 'initialize' }).method).toBe('initialize');
  });
});
