/* Utils.js - Helper functions for simulation */

const Utils = {
    randomInt: (min, max) => Math.floor(Math.random() * (max - min + 1) ) + min,
    
    randomIP: () => {
        return `${Utils.randomInt(1, 255)}.${Utils.randomInt(0, 255)}.${Utils.randomInt(0, 255)}.${Utils.randomInt(0, 255)}`;
    },

    randomCountry: () => {
        const countries = ['USA', 'China', 'Russia', 'Germany', 'Brazil', 'India', 'France'];
        return countries[Math.floor(Math.random() * countries.length)];
    },

    getTime: () => {
        const now = new Date();
        return now.toLocaleTimeString();
    }
};
