import type { Page } from "./types.ts";
import { quickstart } from "./quickstart.ts";
import { howItWorks } from "./how-it-works.ts";
import { cli } from "./cli.ts";
import { coverage } from "./coverage.ts";
import { security } from "./security.ts";
import { pricing } from "./pricing.ts";
import { faq } from "./faq.ts";

export const PAGES: Page[] = [quickstart, howItWorks, cli, coverage, security, pricing, faq];
