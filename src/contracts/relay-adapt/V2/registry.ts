import { Contract, Provider } from 'ethers';
import { ABIRegistry } from '../../../abi/abi';
import { Registry } from '../../../abi/typechain/Registry';

export class RegistryContract {
  private readonly contract: Registry;

  readonly address: string;

  /**
   * Connect to Registry
   * @param deployerAddress - address of Registry
   * @param provider - Network provider
   */
  constructor(deployerAddress: string, provider: Provider) {
    this.address = deployerAddress;
    this.contract = new Contract(
      deployerAddress,
      ABIRegistry,
      provider,
    ) as unknown as Registry;
  }

  async isDeployed(deploymentAddress: string): Promise<boolean> {
    return this.contract.isDeployed(deploymentAddress);
  }
}
