// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Adapter, Helper, Model } from 'casbin';
import * as Sequelize from 'sequelize';

export class CasbinRule extends Sequelize.Model {

  public ptype: string;
  public v0: string;
  public v1: string;
  public v2: string;
  public v3: string;
  public v4: string;
  public v5: string;

  public static buildRule(ptype: string, rule: string[]) {

    const [v0, v1, v2, v3, v4, v5] = rule;
    return new CasbinRule({
      ptype,
      v0: v0 || null,
      v1: v1 || null,
      v2: v2 || null,
      v3: v3 || null,
      v4: v4 || null,
      v5: v5 || null,
    });
  }
}

/**
 * SequelizeAdapter represents the Sequelize adapter for policy storage.
 */
export class SequelizeAdapter implements Adapter {

  private sequelize: Sequelize.Sequelize;

  public init(sequelize: Sequelize.Sequelize) {
    this.sequelize = sequelize;

    return CasbinRule.init({
      ptype: { type: Sequelize.STRING },
      v0: { type: Sequelize.STRING },
      v1: { type: Sequelize.STRING },
      v2: { type: Sequelize.STRING },
      v3: { type: Sequelize.STRING },
      v4: { type: Sequelize.STRING },
      v5: { type: Sequelize.STRING },
    }, { sequelize, modelName: 'casbin_rules' });
  }

  /**
   * loadPolicy loads all policy rules from the storage.
   */
  public async loadPolicy(model: Model) {
    const lines = await CasbinRule.findAll();

    for (const line of lines) {
      const result = line.ptype + ', ' + [line.v0, line.v1, line.v2, line.v3, line.v4, line.v5].filter(n => n).join(', ');
      Helper.loadPolicyLine(result, model);
    }
  }

  /**
   * savePolicy saves all policy rules to the storage.
   */
  public async savePolicy(model: Model) {
    const tx = await this.sequelize.transaction();

    try {
      await CasbinRule.destroy({where: {}, truncate: true, transaction: tx});
      const lines: CasbinRule[] = [];

      let astMap = model.model.get('p')!;
      for (const [ptype, ast] of astMap) {
        for (const rule of ast.policy) {
          const line = CasbinRule.buildRule(ptype, rule);
          lines.push(line);
        }
      }

      astMap = model.model.get('g')!;
      for (const [ptype, ast] of astMap) {
        for (const rule of ast.policy) {
          const line = CasbinRule.buildRule(ptype, rule);
          lines.push(line);
        }
      }

      await CasbinRule.bulkCreate(lines.map(l => l.get({ plain: true})), { transaction: tx });
      tx.commit();
    } catch (ex) {
      tx.rollback();
      throw ex;
    }
    return true;
  }

  /**
   * addPolicy adds a policy rule to the storage.
   */
  public async addPolicy(sec: string, ptype: string, rule: string[]) {
    const line = CasbinRule.buildRule(ptype, rule);
    await line.save();
  }

  /**
   * removePolicy removes a policy rule from the storage.
   */
  public async removePolicy(sec: string, ptype: string, rule: string[]) {
    const line = CasbinRule.buildRule(ptype, rule);
    const where = line.get({ plain: true }) as { [key: string]: string };
    delete where.id;
    await CasbinRule.destroy({ where });
  }

  /**
   * removeFilteredPolicy removes policy rules that match the filter from the storage.
   */
  public async removeFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]) {
    throw new Error('not implemented');
  }
}
