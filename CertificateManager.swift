//
//  CertificateManager.swift
//  oneGuard
//
//  Created by Joseph Cha on 2022/11/20.
//  Copyright © 2022 Michael Frederick. All rights reserved.
//

import Foundation

final class CertificateManager: NSObject {
    @objc static public func isCertificateTrusted() -> Bool {
        guard let path = Bundle.main.path(forResource: <#인증서이름#>, ofType: <#인증서확장자#>, inDirectory: <#프로젝트 내 인증서 위치#>),
              let certData = NSData(contentsOfFile: path)
        else { return false }
        
        // 인증서 객체 생성
        guard let certificate = SecCertificateCreateWithData(nil, certData) else { return false }
        
        // 정책 설정
        let policy = SecPolicyCreateBasicX509() // X509 정책일 경우
        
        let certArray = [certificate]
        var optionalTrust: SecTrust? // 신뢰 객체(SecTrust) 생성
        let _ = SecTrustCreateWithCertificates(certArray as AnyObject,
                                                    policy,
                                                    &optionalTrust)
        
        var trustResult: SecTrustResultType = .invalid
        var cfError: CFError?
        
        if #available(iOS 13.0, *) {
            // iOS 13.0 이상
            let isCertTrusted = SecTrustEvaluateWithError(optionalTrust!, &cfError)
            let _ = SecTrustGetTrustResult(optionalTrust!, &trustResult)
            print("신뢰여부: \(isCertTrusted), 에러사유: \(cfError?.localizedDescription ?? "")")
            
            if let resultDic = SecTrustCopyResult(optionalTrust!) {
                print("resultDic: \(resultDic)")
            }
        } else {
            // iOS 13.0 미만
            let error = SecTrustEvaluate(optionalTrust!, &trustResult)
        }
        print("신뢰결과: \(trustResult.description)")
        return true
    }
}

private extension SecTrustResultType {
    var description: String {
        switch self {
        case .invalid:
            return "invalid"
        case .proceed:
            return "proceed"
        case .deny:
            return "deny"
        case .unspecified:
            return "unspecified"
        case .recoverableTrustFailure:
            return "recoverableTrustFailure"
        case .fatalTrustFailure:
            return "fatalTrustFailure"
        case .otherError:
            return "otherError"
        @unknown default:
            return "알수없는 에러"
        }
    }
}
