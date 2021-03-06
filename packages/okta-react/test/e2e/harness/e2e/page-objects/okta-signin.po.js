import { browser, by, element, ExpectedConditions } from 'protractor';

export class OktaSignInPage {
    waitUntilVisible() {
      browser.wait(ExpectedConditions.presenceOf(this.getSubmitButton()), 5000);
    }

    getUsernameField() {
      return element(by.id('okta-signin-username'));
    }

    getPasswordField() {
      return element(by.id('okta-signin-password'));
    }

    getSubmitButton() {
      return element(by.id('okta-signin-submit'));
    }

    signIn({username, password}) {
      this.getUsernameField().sendKeys(username);
      this.getPasswordField().sendKeys(password);
      this.getSubmitButton().click();
    }
}
