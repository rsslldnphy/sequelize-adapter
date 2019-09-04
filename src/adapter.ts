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

import {Adapter, Helper, Model} from 'casbin';
import * as Sequelize from 'sequelize';
import { CasbinRule, initModel } from './casbinRule';

/**
 * SequelizeAdapter represents the Sequelize adapter for policy storage.
 */
export class SequelizeAdapter implements Adapter {
    private sequelize: Sequelize.Sequelize;
    private CasbinRule: Sequelize.Model;
    private isOwnSequelizeInstance: boolean;

    constructor(option: Sequelize.Options | Sequelize.Sequelize) {
      if (option instanceof Sequelize.Sequelize) {
        this.sequelize = option;
        this.isOwnSequelizeInstance = false;
      } else {
        this.sequelize = new Sequelize.Sequelize(option);
        this.isOwnSequelizeInstance = true;
      }
    }

    /**
     * newAdapter is the constructor.
     * @param option sequelize connection option
     */
    public static async newAdapter(option: Sequelize.Options | Sequelize.Sequelize) {
        const a = new SequelizeAdapter(option);
        await a.open();
        return a;
    }

    private async open() {
        initModel(this.sequelize);
    }

    public async close() {
      if (this.isOwnSequelizeInstance) {
        await this.sequelize.close();
      }
    }

    private async truncateTable() {
        await CasbinRule.destroy({where: {}, truncate: true});
    }

    private loadPolicyLine(line: CasbinRule, model: Model) {
        const result = line.ptype + ', ' + [line.v0, line.v1, line.v2, line.v3, line.v4, line.v5].filter(n => n).join(', ');
        Helper.loadPolicyLine(result, model);
    }

    /**
     * loadPolicy loads all policy rules from the storage.
     */
    public async loadPolicy(model: Model) {
        const lines = await CasbinRule.findAll();

        for (const line of lines) {
            this.loadPolicyLine(line, model);
        }
    }

    private savePolicyLine(ptype: string, rule: string[]): CasbinRule {
        const line = new CasbinRule();

        line.ptype = ptype;
        if (rule.length > 0) {
            line.v0 = rule[0];
        }
        if (rule.length > 1) {
            line.v1 = rule[1];
        }
        if (rule.length > 2) {
            line.v2 = rule[2];
        }
        if (rule.length > 3) {
            line.v3 = rule[3];
        }
        if (rule.length > 4) {
            line.v4 = rule[4];
        }
        if (rule.length > 5) {
            line.v5 = rule[5];
        }

        return line;
    }

    /**
     * savePolicy saves all policy rules to the storage.
     */
    public async savePolicy(model: Model) {
        await this.truncateTable();

        let astMap = model.model.get('p')!;
        for (const [ptype, ast] of astMap) {
            for (const rule of ast.policy) {
                const line = this.savePolicyLine(ptype, rule);
                await line.save();
            }
        }

        astMap = model.model.get('g')!;
        for (const [ptype, ast] of astMap) {
            for (const rule of ast.policy) {
                const line = this.savePolicyLine(ptype, rule);
                await line.save();
            }
        }

        return true;
    }

    /**
     * addPolicy adds a policy rule to the storage.
     */
    public async addPolicy(sec: string, ptype: string, rule: string[]) {
        const line = this.savePolicyLine(ptype, rule);
        await line.save();
    }

    /**
     * removePolicy removes a policy rule from the storage.
     */
    public async removePolicy(sec: string, ptype: string, rule: string[]) {
        const line = this.savePolicyLine(ptype, rule);
        const where = {};

        Object.keys(line.get({plain: true}))
            .filter(key => key !== 'id')
            .forEach(key => {
                // @ts-ignore
                where[key] = line[key];
            });

        await CasbinRule.destroy({where});
    }

    /**
     * removeFilteredPolicy removes policy rules that match the filter from the storage.
     */
    public async removeFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]) {
        throw new Error('not implemented');
    }
}
