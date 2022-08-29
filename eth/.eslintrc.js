module.exports = {
    env: {
        browser: false,
        es2021: true,
        mocha: true,
        node: true
    },
    plugins: ["node", "prettier"],
    extends: ["eslint:recommended", "plugin:node/recommended", "plugin:prettier/recommended", "prettier"],
    globals: {
        abi: false, // Equivalent to "readonly"
        artifacts: false,
        contract: false
    },
    parserOptions: {
        // ecmaVersion: 12, // Equivalent to 2021, and automatically sets by `es2021`
        sourceType: "module"
    },
    root: true,
    rules: {
        "quotes": ["error", "double"],
        "eol-last": ["error"],
        "max-len": [
            "error",
            { "code": 120, "ignoreUrls": true }
        ],
        "no-trailing-spaces": ["error"]
    },
    overrides: [
        {
            files: ["hardhat.config.js"],
            // globals: {
            //     task: true // Equivalent to "writable"
            // }
        }
    ]
};
