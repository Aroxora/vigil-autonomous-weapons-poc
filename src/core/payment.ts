/**
 * Vigil Payment Gateway — RMB Freelancing Contract Settlement
 *
 * All services are sold via formal freelancing contracts with RMB (CNY) settlement.
 * No Stripe, no USD pricing. Clients contact team for contracts.
 */

export interface FreelanceService {
  id: string;
  name: string;
  nameZh: string;
  priceRangeRMB: string;
  unit: string;
  description: string;
}

export const FREELANCE_SERVICES: FreelanceService[] = [
  {
    id: 'basic-pentest', name: 'Basic Pentest', nameZh: '基础渗透测试',
    priceRangeRMB: '¥5,000–15,000', unit: '/合同',
    description: 'Full-scope penetration testing for web apps, network infrastructure, mobile apps, and APIs.',
  },
  {
    id: 'vuln-research', name: 'Vuln Research', nameZh: '漏洞挖掘',
    priceRangeRMB: '¥10,000–50,000', unit: '/合同',
    description: 'Deep vulnerability research targeting specified software, firmware, or protocols.',
  },
  {
    id: 'code-audit', name: 'Code Audit', nameZh: '代码审计',
    priceRangeRMB: '¥8,000–30,000', unit: '/合同',
    description: 'Manual + automated source code security audit covering multiple languages.',
  },
  {
    id: 'consulting', name: 'Consulting', nameZh: '安全咨询',
    priceRangeRMB: '¥3,000–10,000', unit: '/月',
    description: 'Enterprise security architecture design, SDL process development, compliance gap analysis.',
  },
  {
    id: 'incident-response', name: 'Incident Response', nameZh: '应急响应',
    priceRangeRMB: '¥15,000–50,000', unit: '/事件',
    description: 'Security incident response: intrusion analysis, malware RE, log forensics.',
  },
  {
    id: 'exploit-dev', name: 'Exploit Development', nameZh: 'Exploit开发',
    priceRangeRMB: '¥20,000–80,000', unit: '/合同',
    description: 'Custom exploit development for authorized testing only.',
  },
  {
    id: 'red-team', name: 'Red Team Exercise', nameZh: '红队演练',
    priceRangeRMB: '¥30,000–100,000', unit: '/合同',
    description: 'Full-spectrum red team exercise simulating APT kill chain.',
  },
  {
    id: 'training', name: 'Training', nameZh: '培训服务',
    priceRangeRMB: '¥5,000–20,000', unit: '/天',
    description: 'Enterprise security training: hands-on pentesting, secure coding, IR procedures.',
  },
];

export const paymentGateway = {
  services: FREELANCE_SERVICES,
};
