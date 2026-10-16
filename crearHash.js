import bcrypt from 'bcryptjs';

const hash = await bcrypt.hash('rafa', 10);

console.log('Hash generado:', hash);