// SPDX-License-Identifier: MIT
// wrapped LONG Coin (wLONG). This is a token obtained by burning a LONG COIN to an address 
// without a private key: 1111111111111111111114oLvT2. After burning you get a unique coupon 
// in the amount of burned LONG. This coupon is used to top up wLONG at an address 
// in Binance Smart Chain or Ethereum network.

pragma solidity ^0.8.0;

import "./ERC20.sol";
import "./Context.sol";
import "./Ownable.sol";


contract wLONG is ERC20, Ownable {

    constructor() ERC20("wrapped LONG","wLONG") {
    }
    /** @dev 
     * decimals столькоже сколько и в орегинальном LONG coin, totalSupply изначально 0, так как
     * токены минтятся юзерами через купоны, подтверждающие сжигание LONG
    */
    function decimals() public view virtual override returns (uint8) {
        return 0;
    }

    /////////////////////// А теперь все таинство минтинга обернутой монеты за счет газа минтера ///////////////////////////////

    /** @dev
     * Для проверки купонов на сожженный LONG используем механизм ECDSA-подписи, 
     * где r-часть юзабельна как одноразовый лицензионный ключ.
     * Чтобы не было подделок нужно r=k*G генерировать каждый раз из нового случайного k (nonce)!!!
     * При такой схеме в хешь сообщения включается число сожженных LONG а восстанавливаемый при проверке 
     * сигнатуры адрес (публичный ключь) - это _owner-адрес в контракте (возможна его смена при компроментации)
     * Важно! Для предотвращения Front Running в хешь сообщения подмешивается также адрес отправителя (_msgSender()),
     * то есть купоны на сжигание всегда именные и заюзать с другого адреса невозможно
     * 
    */

    mapping(bytes32 => bool) private _rset;    // r-част подписи созданная из случайного k mod n ( r = k*G  mod n)
                                               // ее достаточно для обеспечения уникальности купона при не повторяемых k
                                               // фактически это и есть купон с приватным ключем k, где r - его публичный ключь

    /** @dev
     * Это единственный метод для минтинга wLONG. Вызывающий адрес долже предоставить валидную
     * сигнатуру (купон), полученную после сжигагия орегинальных LONG в количестве amount
    */
    function mint(uint256 amount, bytes memory signature) external virtual returns (bool) {
        //require(signature.length == 64, "wLONG: invalid signature length");

        address minter=_msgSender();

        bytes32 r; bytes32 s; 
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
        }
        require(!_rset[r], "wLONG: key has already been used");

        bytes32 h = keccak256(abi.encodePacked(minter,"\x19\x01",amount)); // Хешь сообщения, содержащего число wLONG, и примесь минтера

        /** @dev
         * При восстановлении точки публичного ключа (адреса) есть неоднозначность (malleable) в сигнатуре вида +-s mod n,
         * которая даст один и тот-же адрес. Поскольку r сохраняется в контракте, то второй раз использовать "противоположную"
         * s не удастся. Поскольку сигнатура генерится из случайного k, а ecrecover() предполагает восстановление из 
         * malleable-сигнатур, мы вынуждены проверить два варианта для v ∈ {27, 28} без лишних заморочек, тратящих газ.
        */
        address signer1 = ecrecover(h, uint8(27), r, s); address signer2 = ecrecover(h, uint8(28), r, s);
        require(signer1==owner() || signer2==owner(), "wLONG: signature is not valid"); // Проверка публичного ключа подписанта

        // Если сюда дошли, то можно минтить wLONG
        _rset[r]=true;          // Купон одноразовый (запоминаем его)
        _mint(minter, amount);  // Инкрементарная (адрес на 0 проверит)
        
        return true;
    }
}