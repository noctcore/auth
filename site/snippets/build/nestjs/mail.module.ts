import { Global, Module } from '@nestjs/common';
import type { Mailer } from '@noctcore/auth';

export const MAILER = Symbol('mailer');

// Swap this for the queue from "Mail into your templates and queue".
const devMailer: Mailer = {
  send: async (event) => void process.stdout.write(`[mail] ${event.type} to ${event.to}\n`),
};

@Global()
@Module({ providers: [{ provide: MAILER, useValue: devMailer }], exports: [MAILER] })
export class MailModule {}
