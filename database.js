// database.js - Database adapter to replace Map-based storage
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

let prisma;

// Initialize Prisma client
export function initDatabase() {
  if (!prisma) {
    prisma = new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'info', 'warn', 'error'] : ['warn', 'error'],
    });
  }
  return prisma;
}

// Database operations to replace your Map-based installs
export class InstallsDB {
  constructor(encryptionKey) {
    this.prisma = initDatabase();
    this.encKey = encryptionKey;
  }

  // Encrypt token (same logic as your existing code)
  encryptToken(token) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.encKey, iv);
    const encrypted = Buffer.concat([cipher.update(Buffer.from(token, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, encrypted]).toString('base64');
  }

  // Decrypt token (same logic as your existing code)
  decryptToken(encryptedToken) {
    const buffer = Buffer.from(encryptedToken, 'base64');
    const iv = buffer.subarray(0, 12);
    const tag = buffer.subarray(12, 28);
    const encrypted = buffer.subarray(28);
    
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  }

  // Replace installs.set(locationId, data)
  async set(locationId, data) {
    const encryptedAccessToken = this.encryptToken(data.access_token);
    const encryptedRefreshToken = this.encryptToken(data.refresh_token);
    
    await this.prisma.install.upsert({
      where: { locationId },
      update: {
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
        expiresAt: BigInt(data.expires_at),
        updatedAt: new Date()
      },
      create: {
        locationId,
        accessToken: encryptedAccessToken,
        refreshToken: encryptedRefreshToken,
        expiresAt: BigInt(data.expires_at)
      }
    });
  }

  // Replace installs.get(locationId)
  async get(locationId) {
    const install = await this.prisma.install.findUnique({
      where: { locationId }
    });
    
    if (!install) return null;
    
    return {
      access_token: this.decryptToken(install.accessToken),
      refresh_token: this.decryptToken(install.refreshToken),
      expires_at: Number(install.expiresAt)
    };
  }

  // Replace installs.has(locationId)
  async has(locationId) {
    const install = await this.prisma.install.findUnique({
      where: { locationId },
      select: { id: true }
    });
    return !!install;
  }

  // Replace installs.size
  async size() {
    return await this.prisma.install.count();
  }

  // Delete installation (for uninstall)
  async delete(locationId) {
    try {
      await this.prisma.install.delete({
        where: { locationId }
      });
    } catch (e) {
      // Ignore if record doesn't exist (P2025 error)
      if (e.code !== 'P2025') {
        throw e;
      }
    }
  }

  // List all installations (for admin/debug)
  async list() {
    const installs = await this.prisma.install.findMany({
      select: {
        locationId: true,
        expiresAt: true,
        createdAt: true,
        updatedAt: true
      }
    });
    
    return installs.map(install => ({
      locationId: install.locationId,
      expires_at: Number(install.expiresAt),
      createdAt: install.createdAt,
      updatedAt: install.updatedAt
    }));
  }

  // Graceful shutdown
  async disconnect() {
    await this.prisma.$disconnect();
  }
}
