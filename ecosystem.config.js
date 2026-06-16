module.exports = {
  apps: [{
    name: "apiswitch",
    script: "src/index.js",
    instances: 1,
    autorestart: true,
    watch: false,
    env: {
      NODE_ENV: "production",
      PORT: 4002
    }
  }]
};
