/**
 * Copyright (c) SAGE3 Development Team 2022. All Rights Reserved
 * University of Hawaii, University of Illinois Chicago, Virginia Tech
 *
 * Distributed under the terms of the SAGE3 License.  The full license is in
 * the file LICENSE, distributed as part of this software.
 */

import * as passport from 'passport';
import { Issuer, custom } from 'openid-client';
import { Strategy, VerifyCallback } from 'passport-openidconnect';

import { SBAuthDB } from '../SBAuthDatabase';

export type SBAuthEinfraConfig = {
  clientID: string;
  clientSecret?: string;
  routeEndpoint: string;
  callbackURL: string;
};

// URL to query for information
const EinfraURL = 'https://login.e-infra.cz/oidc/.well-known/openid-configuration';

/**
 * Setup function of the Einfra Passport Strategy.
 * @param router The express router
 */
export async function passportEinfraSetup(config: SBAuthEinfraConfig) {
  // Increase timeout to 10 seconds
  custom.setHttpOptionsDefaults({ timeout: 10000 });
  // Get information from Einfra
  const einfra = await Issuer.discover(EinfraURL).catch(function (err) {
    console.log('Einfra login> Failed to get Einfra information', err);
  });
  if (einfra) {
    console.log('Einfra login> Received Einfra information', einfra.issuer);
    // Pass it along with site-specific info
    const einfraConfig = {
      // Einfra info
      issuer: einfra.issuer,
      authorizationURL: einfra.authorization_endpoint,
      tokenURL: einfra.token_endpoint,
      userInfoURL: einfra.userinfo_endpoint,

      // site specific info
      clientID: config.clientID,
      callbackURL: config.callbackURL,
    } as any;
    // add the secret if specified
    if (config.clientSecret) einfraConfig.clientSecret = config.clientSecret;

    passport.use(
      'openidconnect-einfra',
      new Strategy(
        einfraConfig,
        async (_issuer: string, profile: passport.Profile, _context: unknown, _refreshToken: unknown, done: VerifyCallback) => {
          const email = profile.emails ? profile.emails[0].value : '';
          const displayName = profile.displayName ? profile.displayName : email.split('@')[0];
          const picture = profile.photos ? profile.photos[0].value : '';
          const extras = {
            displayName: displayName ?? '',
            email: email ?? '',
            picture: picture ?? '',
          };
          const authRecord = await SBAuthDB.findOrAddAuth('einfra', profile.id, extras);
          if (authRecord != undefined) {
            done(null, authRecord);
          } else {
            done(null, false);
          }
        }
      )
    );
    console.log('Einfra login> Setup done');
    return true;
  } else {
    console.log('Einfra login> Failed setup');
    return false;
  }
}
