// Спільний демо-вхід для показу Fineko CRM (06.11): акаунт + доступ до двох демо-магазинів у продукті crm.
// Пароль генерується тут і друкується один раз; повторний запуск пароль НЕ міняє (--reset-password — згенерує новий).
// Запуск на сервері SSO: node scripts/create-demo-user.cjs <projectId1> <projectId2> [--reset-password] [--email demo@fineko.space]
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const prisma = new PrismaClient();
const args = process.argv.slice(2);
const flag = (n) => args.includes(n);
const val = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const projectIds = args.filter((a, i) => !a.startsWith('--') && args[i - 1] !== '--email');
const email = String(val('--email', 'demo@fineko.space')).toLowerCase();

(async () => {
  if (!projectIds.length) throw new Error('Вкажіть id демо-магазинів');
  let user = await prisma.user.findUnique({ where: { email } });
  let password = null;
  if (!user || flag('--reset-password')) {
    password = crypto.randomBytes(9).toString('base64').replace(/[+/=]/g, 'x').slice(0, 12);
    const passwordHash = await bcrypt.hash(password, 10);
    user = user
      ? await prisma.user.update({ where: { id: user.id }, data: { passwordHash, status: 'active' } })
      : await prisma.user.create({ data: { email, passwordHash, displayName: 'Демо Fineko CRM', identities: { create: { provider: 'password', providerUserId: email, email } } } });
  }
  const cur = await prisma.access.findUnique({ where: { userId_product: { userId: user.id, product: 'crm' } } });
  if (cur && cur.role === 'superadmin') throw new Error('Цей акаунт суперадмін: демо-вхід не можна на нього вішати');
  await prisma.access.upsert({
    where: { userId_product: { userId: user.id, product: 'crm' } },
    update: { role: 'user', projectIds: JSON.stringify(projectIds), pageIds: '[]', canEdit: true },
    create: { userId: user.id, product: 'crm', role: 'user', projectIds: JSON.stringify(projectIds), pageIds: '[]', canEdit: true },
  });
  console.log('Логін:', email);
  console.log('Пароль:', password || '(не змінювався; --reset-password згенерує новий)');
  console.log('Доступ до магазинів:', projectIds.join(', '));
})().catch((e) => { console.error(e.message); process.exit(1); }).finally(() => prisma.$disconnect());
