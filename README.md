# VacciReg Mali Web — version prête à déployer

## Contenu
- Backend Node.js / Express
- SQLite avec mode WAL
- Authentification JWT + mots de passe bcrypt
- Rôles `admin` et `agent`
- Centres de santé
- Personnes et vaccinations
- Tableau de bord
- Journal d'audit
- Frontend web responsive servi par le backend
- Configuration `.env.example`

## Lancer en local
1. Installer Node.js 20+.
2. `cd backend`
3. `npm install`
4. Copier `.env.example` vers `.env`
5. Modifier impérativement `JWT_SECRET` et `ADMIN_PASSWORD`.
6. `npm start`
7. Ouvrir `http://localhost:3000`

## Déploiement recommandé
Déployer le dossier sur un serveur Linux/VPS ou une plateforme Node.js. Utiliser HTTPS (reverse proxy Nginx/Caddy ou service managé), une base de données sauvegardée, des sauvegardes chiffrées et des secrets d'environnement.

## Avant de stocker de vraies données médicales
Cette archive est une base prête à déployer techniquement, mais elle doit être auditée et durcie avant production médicale : HTTPS obligatoire, politique de conservation, chiffrement/gestion des clés, sauvegardes, contrôle d'accès fin, rotation des secrets, limitation de débit, supervision, restauration testée et conformité aux règles locales de protection des données.

## Identifiants initiaux
Ils sont définis par `ADMIN_EMAIL` et `ADMIN_PASSWORD` dans `.env`. Changez le mot de passe avant exposition publique.
